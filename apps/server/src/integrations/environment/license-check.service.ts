import { Injectable } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { EnvironmentService } from './environment.service';
import { Feature } from '../../common/features';

@Injectable()
export class LicenseCheckService {
  constructor(
    private moduleRef: ModuleRef,
    private environmentService: EnvironmentService,
  ) {}

  /**
   * Features implemented natively in this fork rather than by the (absent)
   * enterprise submodule, so they are reported as available without a license.
   *
   * Kept to an explicit short list on purpose. A generic env-driven feature list
   * would let an operator switch on features whose server implementations live
   * in the `ee` submodule (ai, scim, page:permissions, ...), producing broken UI
   * or runtime errors. These two are the ones we actually built:
   *
   *  - SSO_CUSTOM        the OIDC provider form and the enforce-SSO toggle
   *  - SECURITY_SETTINGS the "Security & SSO" nav item
   *
   * Enabling SECURITY_SETTINGS also makes WorkspaceService.update accept
   * disablePublicSharing / trashRetentionDays / restrictApiToAdmins /
   * allowMemberTemplates. That is harmless: each of those has its own client
   * feature gate (SHARING_CONTROLS, RETENTION, ...) which stays off, and the
   * server-side behaviour for them lives in the core.
   */
  private selfBuiltFeatures(): string[] {
    if (this.environmentService.isCloud()) return [];
    return this.environmentService.isSsoOidcEnabled()
      ? [Feature.SSO_CUSTOM, Feature.SECURITY_SETTINGS]
      : [];
  }

  isValidEELicense(licenseKey: string): boolean {
    if (this.environmentService.isCloud()) {
      return true;
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const LicenseModule = require('../../ee/licence/license.service');
      const licenseService = this.moduleRef.get(LicenseModule.LicenseService, {
        strict: false,
      });
      return licenseService.isValidEELicense(licenseKey);
    } catch {
      return false;
    }
  }

  hasFeature(licenseKey: string, feature: string, plan?: string): boolean {
    if (this.selfBuiltFeatures().includes(feature)) {
      return true;
    }

    if (this.environmentService.isCloud()) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { getFeaturesForCloudPlan } = require('../../ee/licence/feature-registry');
        return getFeaturesForCloudPlan(plan).has(feature);
      } catch {
        return false;
      }
    }

    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const LicenseModule = require('../../ee/licence/license.service');
      const licenseService = this.moduleRef.get(LicenseModule.LicenseService, {
        strict: false,
      });
      return licenseService.hasFeature(licenseKey, feature);
    } catch {
      return false;
    }
  }

  getFeatures(licenseKey: string): string[] {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const LicenseModule = require('../../ee/licence/license.service');
      const licenseService = this.moduleRef.get(LicenseModule.LicenseService, {
        strict: false,
      });
      return licenseService.getFeatures(licenseKey);
    } catch {
      return [];
    }
  }

  resolveFeatures(licenseKey: string, plan: string): string[] {
    if (this.environmentService.isCloud()) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { getFeaturesForCloudPlan } = require('../../ee/licence/feature-registry');
        return [...getFeaturesForCloudPlan(plan)];
      } catch {
        return [];
      }
    }

    return [
      ...new Set([...this.getFeatures(licenseKey), ...this.selfBuiltFeatures()]),
    ];
  }

  resolveTier(licenseKey: string, plan: string): string {
    if (this.environmentService.isCloud()) {
      return plan ?? 'standard';
    }

    return this.getLicenseType(licenseKey) ?? 'free';
  }

  private getLicenseType(licenseKey: string): string | null {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const LicenseModule = require('../../ee/licence/license.service');
      const licenseService = this.moduleRef.get(LicenseModule.LicenseService, {
        strict: false,
      });
      return licenseService.getLicenseType(licenseKey);
    } catch {
      return null;
    }
  }
}
