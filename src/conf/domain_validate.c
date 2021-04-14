/*
 * domain_validate.c: domain general validation functions
 *
 * Copyright IBM Corp, 2020
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "domain_validate.h"
#include "domain_conf.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.domain_validate");

/**
 * virDomainDiskAddressDiskBusCompatibility:
 * @bus: disk bus type
 * @addressType: disk address type
 *
 * Check if the specified disk address type @addressType is compatible
 * with the specified disk bus type @bus. This function checks
 * compatibility with the bus types SATA, SCSI, FDC, and IDE only,
 * because only these are handled in common code.
 *
 * Returns true if compatible or can't be decided in common code,
 *         false if known to be not compatible.
 */
static bool
virDomainDiskAddressDiskBusCompatibility(virDomainDiskBus bus,
                                         virDomainDeviceAddressType addressType)
{
    if (addressType == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        return true;

    switch (bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
    case VIR_DOMAIN_DISK_BUS_FDC:
    case VIR_DOMAIN_DISK_BUS_SCSI:
    case VIR_DOMAIN_DISK_BUS_SATA:
        return addressType == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_LAST:
        return true;
    }

    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("unexpected bus type '%d'"),
                   bus);
    return true;
}


int
virSecurityDeviceLabelDefValidateXML(virSecurityDeviceLabelDefPtr *seclabels,
                                     size_t nseclabels,
                                     virSecurityLabelDefPtr *vmSeclabels,
                                     size_t nvmSeclabels)
{
    virSecurityDeviceLabelDefPtr seclabel;
    size_t i;
    size_t j;

    for (i = 0; i < nseclabels; i++) {
        seclabel = seclabels[i];

        /* find the security label that it's being overridden */
        for (j = 0; j < nvmSeclabels; j++) {
            if (STRNEQ_NULLABLE(vmSeclabels[j]->model, seclabel->model))
                continue;

            if (!vmSeclabels[j]->relabel) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("label overrides require relabeling to be "
                                 "enabled at the domain level"));
                return -1;
            }
        }
    }

    return 0;
}


static int
virDomainDiskDefValidateSourceChainOne(const virStorageSource *src)
{
    if (src->type == VIR_STORAGE_TYPE_NETWORK && src->auth) {
        virStorageAuthDef *authdef = src->auth;
        int actUsage;

        if ((actUsage = virSecretUsageTypeFromString(authdef->secrettype)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown secret type '%s'"),
                           NULLSTR(authdef->secrettype));
            return -1;
        }

        if ((src->protocol == VIR_STORAGE_NET_PROTOCOL_ISCSI &&
             actUsage != VIR_SECRET_USAGE_TYPE_ISCSI) ||
            (src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD &&
             actUsage != VIR_SECRET_USAGE_TYPE_CEPH)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("invalid secret type '%s'"),
                           virSecretUsageTypeToString(actUsage));
            return -1;
        }
    }

    if (src->encryption) {
        virStorageEncryption *encryption = src->encryption;

        if (encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS &&
            encryption->encinfo.cipher_name) {

            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("supplying <cipher> for domain disk definition "
                             "is unnecessary"));
            return -1;
        }
    }

    return 0;
}


int
virDomainDiskDefValidateSource(const virStorageSource *src)
{
    const virStorageSource *next;

    for (next = src; next; next = next->backingStore) {
        if (virDomainDiskDefValidateSourceChainOne(next) < 0)
            return -1;
    }

    return 0;
}

int
virDomainDiskDefValidate(const virDomainDef *def,
                         const virDomainDiskDef *disk)
{
    virStorageSourcePtr next;

    if (virDomainDiskDefValidateSource(disk->src) < 0)
        return -1;

    /* Validate LUN configuration */
    if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        /* volumes haven't been translated at this point, so accept them */
        if (!(disk->src->type == VIR_STORAGE_TYPE_BLOCK ||
              disk->src->type == VIR_STORAGE_TYPE_VOLUME ||
              (disk->src->type == VIR_STORAGE_TYPE_NETWORK &&
               disk->src->protocol == VIR_STORAGE_NET_PROTOCOL_ISCSI))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' improperly configured for a "
                             "device='lun'"), disk->dst);
            return -1;
        }
    } else {
        if (disk->src->pr) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("<reservations/> allowed only for lun devices"));
            return -1;
        }

        if (disk->rawio != VIR_TRISTATE_BOOL_ABSENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("rawio can be used only with device='lun'"));
            return -1;
        }

        if (disk->sgio != VIR_DOMAIN_DEVICE_SGIO_DEFAULT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("sgio can be used only with device='lun'"));
            return -1;
        }
    }

    /* Reject disks with a bus type that is not compatible with the
     * given address type. The function considers only buses that are
     * handled in common code. For other bus types it's not possible
     * to decide compatibility in common code.
     */
    if (!virDomainDiskAddressDiskBusCompatibility(disk->bus, disk->info.type)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid address type '%s' for the disk '%s' with the bus type '%s'"),
                       virDomainDeviceAddressTypeToString(disk->info.type),
                       disk->dst,
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO) {
        if (disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO ||
            disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO_TRANSITIONAL ||
            disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO_NON_TRANSITIONAL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk model '%s' not supported for bus '%s'"),
                           virDomainDiskModelTypeToString(disk->model),
                           virDomainDiskBusTypeToString(disk->bus));
            return -1;
        }

        if (disk->queues) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("queues attribute in disk driver element is only supported by virtio-blk"));
            return -1;
        }

        if (disk->event_idx != VIR_TRISTATE_SWITCH_ABSENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk event_idx mode supported only for virtio bus"));
            return -1;
        }

        if (disk->ioeventfd != VIR_TRISTATE_SWITCH_ABSENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk ioeventfd mode supported only for virtio bus"));
            return -1;
        }
    }

    if (disk->src->type == VIR_STORAGE_TYPE_NVME) {
        /* NVMe namespaces start from 1 */
        if (disk->src->nvme->namespace == 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("NVMe namespace can't be zero"));
            return -1;
        }
    }

    for (next = disk->src; next; next = next->backingStore) {
        if (virSecurityDeviceLabelDefValidateXML(next->seclabels,
                                                 next->nseclabels,
                                                 def->seclabels,
                                                 def->nseclabels) < 0)
            return -1;
    }

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        disk->bus != VIR_DOMAIN_DISK_BUS_FDC) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid bus type '%s' for floppy disk"),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (disk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        disk->bus == VIR_DOMAIN_DISK_BUS_FDC) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid bus type '%s' for disk"),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (disk->removable != VIR_TRISTATE_SWITCH_ABSENT &&
        disk->bus != VIR_DOMAIN_DISK_BUS_USB) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("removable is only valid for usb disks"));
        return -1;
    }

    if (disk->startupPolicy != VIR_DOMAIN_STARTUP_POLICY_DEFAULT) {
        if (disk->src->type == VIR_STORAGE_TYPE_NETWORK) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Setting disk %s is not allowed for "
                             "disk of network type"),
                           virDomainStartupPolicyTypeToString(disk->startupPolicy));
            return -1;
        }

        if (disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM &&
            disk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
            disk->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_REQUISITE) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Setting disk 'requisite' is allowed only for "
                             "cdrom or floppy"));
            return -1;
        }
    }

    return 0;
}
