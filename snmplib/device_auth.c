/*
 * device_auth.c
 *
 * Version-based per-device authentication model.  See
 * include/net-snmp/library/device_auth.h for the public API.
 */

#include <net-snmp/net-snmp-config.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>
#include <net-snmp/library/asn1.h>
#include <net-snmp/library/snmp.h>
#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/read_config.h>
#include <net-snmp/library/device_auth.h>

#ifdef NETSNMP_SECMOD_USM
#include <net-snmp/library/keytools.h>
#include <net-snmp/library/snmpusm.h>
#include <net-snmp/library/transform_oids.h>
#endif

typedef struct device_auth_node_s {
    netsnmp_device_auth entry;
    struct device_auth_node_s *next;
} device_auth_node;

static device_auth_node *device_auth_list = NULL;
static int              device_auth_list_count = 0;
static int              device_auth_config_registered = 0;

static int
device_auth_version_from_string(const char *str)
{
    if (NULL == str)
        return -1;
    if (0 == strcmp(str, "1"))
        return SNMP_VERSION_1;
    if (0 == strcmp(str, "2") || 0 == strcasecmp(str, "2c"))
        return SNMP_VERSION_2c;
    if (0 == strcmp(str, "3"))
        return SNMP_VERSION_3;
    return -1;
}

#ifdef NETSNMP_SECMOD_USM
static const oid   *
device_auth_auth_proto(const char *name, size_t *oid_len)
{
#ifndef NETSNMP_DISABLE_MD5
    if (0 == strcasecmp(name, "MD5")) {
        *oid_len = OID_LENGTH(usmHMACMD5AuthProtocol);
        return usmHMACMD5AuthProtocol;
    }
#endif
    if (0 == strcasecmp(name, "SHA") || 0 == strcasecmp(name, "SHA1")) {
        *oid_len = OID_LENGTH(usmHMACSHA1AuthProtocol);
        return usmHMACSHA1AuthProtocol;
    }
#ifdef HAVE_EVP_SHA224
    if (0 == strcasecmp(name, "SHA-224") || 0 == strcasecmp(name, "SHA224")) {
        *oid_len = OID_LENGTH(usmHMAC128SHA224AuthProtocol);
        return usmHMAC128SHA224AuthProtocol;
    }
    if (0 == strcasecmp(name, "SHA-256") || 0 == strcasecmp(name, "SHA256")) {
        *oid_len = OID_LENGTH(usmHMAC192SHA256AuthProtocol);
        return usmHMAC192SHA256AuthProtocol;
    }
#endif
#ifdef HAVE_EVP_SHA384
    if (0 == strcasecmp(name, "SHA-384") || 0 == strcasecmp(name, "SHA384")) {
        *oid_len = OID_LENGTH(usmHMAC256SHA384AuthProtocol);
        return usmHMAC256SHA384AuthProtocol;
    }
    if (0 == strcasecmp(name, "SHA-512") || 0 == strcasecmp(name, "SHA512")) {
        *oid_len = OID_LENGTH(usmHMAC384SHA512AuthProtocol);
        return usmHMAC384SHA512AuthProtocol;
    }
#endif
    return NULL;
}

static const oid   *
device_auth_priv_proto(const char *name, size_t *oid_len)
{
#ifndef NETSNMP_DISABLE_DES
    if (0 == strcasecmp(name, "DES")) {
        *oid_len = OID_LENGTH(usmDESPrivProtocol);
        return usmDESPrivProtocol;
    }
#endif
    if (0 == strcasecmp(name, "AES") || 0 == strcasecmp(name, "AES128")
        || 0 == strcasecmp(name, "AES-128")) {
        *oid_len = OID_LENGTH(usmAESPrivProtocol);
        return usmAESPrivProtocol;
    }
    return NULL;
}
#endif                          /* NETSNMP_SECMOD_USM */

static int
device_auth_sec_level(const char *name, int *level)
{
    if (0 == strcasecmp(name, "noAuthNoPriv"))
        *level = SNMP_SEC_LEVEL_NOAUTH;
    else if (0 == strcasecmp(name, "authNoPriv"))
        *level = SNMP_SEC_LEVEL_AUTHNOPRIV;
    else if (0 == strcasecmp(name, "authPriv"))
        *level = SNMP_SEC_LEVEL_AUTHPRIV;
    else
        return SNMPERR_VALUE;
    return SNMPERR_SUCCESS;
}

static int
device_auth_set_string(char **dst, const char *src)
{
    char           *copy = strdup(src);

    if (NULL == copy)
        return SNMPERR_MALLOC;
    SNMP_FREE(*dst);
    *dst = copy;
    return SNMPERR_SUCCESS;
}

static void
device_auth_free_contents(netsnmp_device_auth *entry)
{
    SNMP_FREE(entry->device);
    SNMP_FREE(entry->community);
    SNMP_FREE(entry->sec_name);
    SNMP_FREE(entry->auth_proto);
    SNMP_FREE(entry->auth_pass);
    SNMP_FREE(entry->priv_proto);
    SNMP_FREE(entry->priv_pass);
}

netsnmp_device_auth *
netsnmp_device_auth_create(const char *device, int version)
{
    netsnmp_device_auth *entry;

    if (NULL == device || '\0' == *device)
        return NULL;
    switch (version) {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
    case SNMP_VERSION_3:
        break;
    default:
        return NULL;
    }

    entry = calloc(1, sizeof(*entry));
    if (NULL == entry)
        return NULL;
    entry->device = strdup(device);
    if (NULL == entry->device) {
        free(entry);
        return NULL;
    }
    entry->version = version;
    entry->sec_level = SNMP_SEC_LEVEL_NOAUTH;
    return entry;
}

void
netsnmp_device_auth_free(netsnmp_device_auth *entry)
{
    if (NULL == entry)
        return;
    device_auth_free_contents(entry);
    free(entry);
}

static device_auth_node *
device_auth_find_node(const char *device)
{
    device_auth_node *node;

    for (node = device_auth_list; node; node = node->next) {
        if (0 == strcmp(node->entry.device, device))
            return node;
    }
    return NULL;
}

int
netsnmp_device_auth_add(netsnmp_device_auth *entry)
{
    device_auth_node *node;

    if (NULL == entry || NULL == entry->device)
        return SNMPERR_GENERR;

    node = device_auth_find_node(entry->device);
    if (node) {
        device_auth_free_contents(&node->entry);
        node->entry = *entry;
        free(entry);
        return SNMPERR_SUCCESS;
    }

    node = calloc(1, sizeof(*node));
    if (NULL == node)
        return SNMPERR_MALLOC;
    node->entry = *entry;
    free(entry);
    node->next = device_auth_list;
    device_auth_list = node;
    device_auth_list_count++;
    return SNMPERR_SUCCESS;
}

netsnmp_device_auth *
netsnmp_device_auth_find(const char *device)
{
    device_auth_node *node;

    if (NULL == device)
        return NULL;
    node = device_auth_find_node(device);
    return node ? &node->entry : NULL;
}

int
netsnmp_device_auth_remove(const char *device)
{
    device_auth_node *node, **prev;

    if (NULL == device)
        return SNMPERR_GENERR;

    for (prev = &device_auth_list, node = device_auth_list;
         node; prev = &node->next, node = node->next) {
        if (0 == strcmp(node->entry.device, device)) {
            *prev = node->next;
            device_auth_free_contents(&node->entry);
            free(node);
            device_auth_list_count--;
            return SNMPERR_SUCCESS;
        }
    }
    return SNMPERR_BAD_NAME;
}

void
netsnmp_device_auth_clear(void)
{
    while (device_auth_list) {
        device_auth_node *node = device_auth_list;

        device_auth_list = node->next;
        device_auth_free_contents(&node->entry);
        free(node);
    }
    device_auth_list_count = 0;
}

int
netsnmp_device_auth_count(void)
{
    return device_auth_list_count;
}

int
netsnmp_device_auth_parse_line(const char *line)
{
    char                device[256], version[32], token[512];
    const char         *cp;
    int                 ver, rc = SNMPERR_SUCCESS;
    netsnmp_device_auth *entry;

    if (NULL == line)
        return SNMPERR_GENERR;

    cp = copy_nword_const(line, device, sizeof(device));
    if ('\0' == device[0])
        return SNMPERR_BAD_NAME;
    cp = copy_nword_const(cp, version, sizeof(version));
    ver = device_auth_version_from_string(version);
    if (-1 == ver)
        return SNMPERR_BAD_VERSION;

    entry = netsnmp_device_auth_create(device, ver);
    if (NULL == entry)
        return SNMPERR_MALLOC;

    while (cp && *cp) {
        char           *value;

        cp = copy_nword_const(cp, token, sizeof(token));
        if ('\0' == token[0])
            break;
        value = strchr(token, '=');
        if (NULL == value || value == token || '\0' == value[1]) {
            rc = SNMPERR_VALUE;
            break;
        }
        *value++ = '\0';

        if (0 == strcasecmp(token, "community"))
            rc = device_auth_set_string(&entry->community, value);
        else if (0 == strcasecmp(token, "secName"))
            rc = device_auth_set_string(&entry->sec_name, value);
        else if (0 == strcasecmp(token, "secLevel"))
            rc = device_auth_sec_level(value, &entry->sec_level);
        else if (0 == strcasecmp(token, "authProto"))
            rc = device_auth_set_string(&entry->auth_proto, value);
        else if (0 == strcasecmp(token, "authPass"))
            rc = device_auth_set_string(&entry->auth_pass, value);
        else if (0 == strcasecmp(token, "privProto"))
            rc = device_auth_set_string(&entry->priv_proto, value);
        else if (0 == strcasecmp(token, "privPass"))
            rc = device_auth_set_string(&entry->priv_pass, value);
        else
            rc = SNMPERR_VALUE;

        if (SNMPERR_SUCCESS != rc)
            break;
    }

    if (SNMPERR_SUCCESS == rc) {
        switch (entry->version) {
        case SNMP_VERSION_1:
        case SNMP_VERSION_2c:
            if (NULL == entry->community)
                rc = SNMPERR_BAD_COMMUNITY;
            break;
        case SNMP_VERSION_3:
            if (NULL == entry->sec_name)
                rc = SNMPERR_BAD_SEC_NAME;
            break;
        }
    }

    if (SNMPERR_SUCCESS != rc) {
        netsnmp_device_auth_free(entry);
        return rc;
    }
    return netsnmp_device_auth_add(entry);
}

int
netsnmp_device_auth_apply(const netsnmp_device_auth *entry,
                          netsnmp_session *session)
{
    if (NULL == entry || NULL == session)
        return SNMPERR_GENERR;

    session->version = entry->version;

    switch (entry->version) {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
        if (NULL == entry->community)
            return SNMPERR_BAD_COMMUNITY;
        SNMP_FREE(session->community);
        session->community = (u_char *) strdup(entry->community);
        if (NULL == session->community)
            return SNMPERR_MALLOC;
        session->community_len = strlen(entry->community);
        break;

    case SNMP_VERSION_3:
#ifdef NETSNMP_SECMOD_USM
    {
        const oid      *proto;
        size_t          proto_len = 0;

        if (NULL == entry->sec_name)
            return SNMPERR_BAD_SEC_NAME;

        SNMP_FREE(session->securityName);
        session->securityName = strdup(entry->sec_name);
        if (NULL == session->securityName)
            return SNMPERR_MALLOC;
        session->securityNameLen = strlen(entry->sec_name);
        session->securityLevel =
            entry->sec_level ? entry->sec_level : SNMP_SEC_LEVEL_NOAUTH;

        if (entry->auth_proto) {
            proto = device_auth_auth_proto(entry->auth_proto, &proto_len);
            if (NULL == proto)
                return SNMPERR_VALUE;
            SNMP_FREE(session->securityAuthProto);
            session->securityAuthProto =
                snmp_duplicate_objid(proto, proto_len);
            session->securityAuthProtoLen = proto_len;
        } else if (entry->auth_pass && NULL == session->securityAuthProto) {
            const oid      *def = get_default_authtype(&proto_len);

            session->securityAuthProto =
                snmp_duplicate_objid(def, proto_len);
            session->securityAuthProtoLen = proto_len;
        }
        if (entry->auth_pass) {
            if (NULL == session->securityAuthProto)
                return SNMPERR_SC_NOT_CONFIGURED;
            session->securityAuthKeyLen = USM_AUTH_KU_LEN;
            if (generate_Ku(session->securityAuthProto,
                            session->securityAuthProtoLen,
                            (const u_char *) entry->auth_pass,
                            strlen(entry->auth_pass),
                            session->securityAuthKey,
                            &session->securityAuthKeyLen) != SNMPERR_SUCCESS)
                return SNMPERR_KT_NOT_AVAILABLE;
        }

        if (entry->priv_proto) {
            proto = device_auth_priv_proto(entry->priv_proto, &proto_len);
            if (NULL == proto)
                return SNMPERR_VALUE;
            SNMP_FREE(session->securityPrivProto);
            session->securityPrivProto =
                snmp_duplicate_objid(proto, proto_len);
            session->securityPrivProtoLen = proto_len;
        } else if (entry->priv_pass && NULL == session->securityPrivProto) {
            const oid      *def = get_default_privtype(&proto_len);

            session->securityPrivProto =
                snmp_duplicate_objid(def, proto_len);
            session->securityPrivProtoLen = proto_len;
        }
        if (entry->priv_pass) {
            if (NULL == session->securityPrivProto
                || NULL == session->securityAuthProto)
                return SNMPERR_SC_NOT_CONFIGURED;
            session->securityPrivKeyLen = USM_PRIV_KU_LEN;
            if (generate_Ku(session->securityAuthProto,
                            session->securityAuthProtoLen,
                            (const u_char *) entry->priv_pass,
                            strlen(entry->priv_pass),
                            session->securityPrivKey,
                            &session->securityPrivKeyLen) != SNMPERR_SUCCESS)
                return SNMPERR_KT_NOT_AVAILABLE;
        }
        break;
    }
#else
        return SNMPERR_UNKNOWN_SEC_MODEL;
#endif                          /* NETSNMP_SECMOD_USM */

    default:
        return SNMPERR_BAD_VERSION;
    }
    return SNMPERR_SUCCESS;
}

int
netsnmp_device_auth_setup_session(netsnmp_session *session,
                                  const char *device)
{
    netsnmp_device_auth *entry;

    if (NULL == session || NULL == device)
        return SNMPERR_GENERR;
    entry = netsnmp_device_auth_find(device);
    if (NULL == entry)
        return SNMPERR_BAD_NAME;
    return netsnmp_device_auth_apply(entry, session);
}

static void
device_auth_config_handler(const char *token, char *line)
{
    int                 rc = netsnmp_device_auth_parse_line(line);

    if (SNMPERR_SUCCESS != rc)
        config_perror("invalid deviceAuth directive");
}

void
netsnmp_device_auth_init(void)
{
    if (device_auth_config_registered)
        return;
    device_auth_config_registered = 1;
    register_config_handler("snmp", "deviceAuth",
                            device_auth_config_handler, NULL,
                            "device 1|2c|3 [key=value ...]");
}
