/*
 * device_auth.h
 *
 * Version-based per-device authentication model.
 *
 * This module implements a registry of per-device authentication
 * parameters.  For each managed device the registry records which
 * SNMP version to use together with the credentials matching that
 * version (community string for SNMPv1/SNMPv2c, USM parameters for
 * SNMPv3).  The stored parameters can be applied to a netsnmp_session
 * before the session is opened, so applications can select the right
 * credentials per device without changing existing API usage.
 *
 * The registry can be populated programmatically or through the
 * "deviceAuth" directive in snmp.conf, e.g.:
 *
 *   deviceAuth 192.0.2.1 1 community=public
 *   deviceAuth 192.0.2.2 2c community=private
 *   deviceAuth 192.0.2.3 3 secName=alice secLevel=authPriv \
 *       authProto=SHA authPass=authpass privProto=AES privPass=privpass
 */

#ifndef NETSNMP_DEVICE_AUTH_H
#define NETSNMP_DEVICE_AUTH_H

#include <net-snmp/library/snmp_api.h>

#ifdef __cplusplus
extern          "C" {
#endif

    /*
     * Per-device authentication entry.  Strings are owned by the
     * entry and freed by netsnmp_device_auth_free().
     */
    typedef struct netsnmp_device_auth_s {
        char           *device;       /* device name or address (key) */
        int             version;      /* SNMP_VERSION_1/2c/3          */
        char           *community;    /* SNMPv1/v2c community string  */
        char           *sec_name;     /* SNMPv3 USM security name     */
        int             sec_level;    /* SNMP_SEC_LEVEL_*             */
        char           *auth_proto;   /* "MD5", "SHA", "SHA-256", ... */
        char           *auth_pass;    /* authentication passphrase    */
        char           *priv_proto;   /* "DES", "AES", ...            */
        char           *priv_pass;    /* privacy passphrase           */
    } netsnmp_device_auth;

    /*
     * Register the "deviceAuth" snmp.conf configuration token.
     * Idempotent; called automatically from the library
     * initialization, but harmless to call again.
     */
    NETSNMP_IMPORT
    void            netsnmp_device_auth_init(void);

    /*
     * Create an empty entry for a device using a given SNMP version.
     * Returns NULL on allocation failure or invalid arguments.
     */
    NETSNMP_IMPORT
    netsnmp_device_auth *netsnmp_device_auth_create(const char *device,
                                                    int version);

    /*
     * Add an entry to the registry, replacing any existing entry for
     * the same device.  Takes ownership of the entry.  Returns
     * SNMPERR_SUCCESS or an SNMPERR_* error code.
     */
    NETSNMP_IMPORT
    int             netsnmp_device_auth_add(netsnmp_device_auth *entry);

    /*
     * Find the entry registered for a device, or NULL.
     */
    NETSNMP_IMPORT
    netsnmp_device_auth *netsnmp_device_auth_find(const char *device);

    /*
     * Remove and free the entry registered for a device.  Returns
     * SNMPERR_SUCCESS or SNMPERR_BAD_NAME if not found.
     */
    NETSNMP_IMPORT
    int             netsnmp_device_auth_remove(const char *device);

    /*
     * Remove and free all registered entries.
     */
    NETSNMP_IMPORT
    void            netsnmp_device_auth_clear(void);

    /*
     * Number of registered entries.
     */
    NETSNMP_IMPORT
    int             netsnmp_device_auth_count(void);

    /*
     * Free a single entry that is not part of the registry.
     */
    NETSNMP_IMPORT
    void            netsnmp_device_auth_free(netsnmp_device_auth *entry);

    /*
     * Parse one "deviceAuth" configuration line:
     *   <device> <version> [key=value ...]
     * and register the resulting entry.  Returns SNMPERR_SUCCESS or
     * an SNMPERR_* error code.
     */
    NETSNMP_IMPORT
    int             netsnmp_device_auth_parse_line(const char *line);

    /*
     * Apply an entry to a session: sets the session version and the
     * version-appropriate credential fields (community for v1/v2c,
     * USM security name/level/protocols/keys for v3).  Passphrases
     * are converted to Ku master keys the same way snmp_parse_args
     * does.  Returns SNMPERR_SUCCESS or an SNMPERR_* error code.
     */
    NETSNMP_IMPORT
    int             netsnmp_device_auth_apply(const netsnmp_device_auth
                                              *entry,
                                              netsnmp_session *session);

    /*
     * Look up the entry for a device and apply it to a session.
     * Returns SNMPERR_BAD_NAME if no entry is registered.
     */
    NETSNMP_IMPORT
    int             netsnmp_device_auth_setup_session(netsnmp_session
                                                      *session,
                                                      const char *device);

#ifdef __cplusplus
}
#endif
#endif                          /* NETSNMP_DEVICE_AUTH_H */
