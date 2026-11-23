/* HEADER Testing the version-based device authentication model API */

#include <net-snmp/library/device_auth.h>

#define NUM_DEVICES 100

{
    int                 i, rc, ok;
    char                device[64], community[64], line[256];
    char                secname[64], authpass[64], privpass[64];
    netsnmp_device_auth *entry, *found;
    netsnmp_session     session;

    init_snmp("T045device_auth");

    /* init is idempotent */
    netsnmp_device_auth_init();
    netsnmp_device_auth_init();
    OK(1, "netsnmp_device_auth_init() is idempotent");

    /*
     * Register 100 devices: versions cycle through v1, v2c and v3.
     */
    for (i = 0; i < NUM_DEVICES; i++) {
        int version;

        snprintf(device, sizeof(device), "device-%03d", i);
        switch (i % 3) {
        case 0:
            version = SNMP_VERSION_1;
            break;
        case 1:
            version = SNMP_VERSION_2c;
            break;
        default:
            version = SNMP_VERSION_3;
            break;
        }
        entry = netsnmp_device_auth_create(device, version);
        OKF(entry != NULL, ("created entry for %s", device));
        if (NULL == entry)
            continue;

        if (SNMP_VERSION_3 == version) {
            snprintf(secname, sizeof(secname), "user-%03d", i);
            snprintf(authpass, sizeof(authpass), "authpass-%03d", i);
            snprintf(privpass, sizeof(privpass), "privpass-%03d", i);
            entry->sec_name = strdup(secname);
            entry->sec_level = SNMP_SEC_LEVEL_AUTHPRIV;
            entry->auth_proto = strdup("SHA");
            entry->auth_pass = strdup(authpass);
            entry->priv_proto = strdup("AES");
            entry->priv_pass = strdup(privpass);
        } else {
            snprintf(community, sizeof(community), "comm-%03d", i);
            entry->community = strdup(community);
        }
        rc = netsnmp_device_auth_add(entry);
        OKF(SNMPERR_SUCCESS == rc, ("added entry for %s", device));
    }

    OKF(NUM_DEVICES == netsnmp_device_auth_count(),
        ("registry holds %d devices", NUM_DEVICES));

    /*
     * Look up each of the 100 devices and apply its entry to a
     * session, verifying the version-appropriate credentials.
     */
    for (i = 0; i < NUM_DEVICES; i++) {
        snprintf(device, sizeof(device), "device-%03d", i);
        found = netsnmp_device_auth_find(device);
        OKF(found != NULL, ("found entry for %s", device));
        if (NULL == found)
            continue;

        snmp_sess_init(&session);
        rc = netsnmp_device_auth_setup_session(&session, device);
        OKF(SNMPERR_SUCCESS == rc, ("applied entry for %s", device));
        if (SNMPERR_SUCCESS != rc)
            continue;

        if (SNMP_VERSION_3 == found->version) {
            snprintf(secname, sizeof(secname), "user-%03d", i);
            ok = session.version == SNMP_VERSION_3 &&
                session.securityName != NULL &&
                0 == strcmp(session.securityName, secname) &&
                session.securityLevel == SNMP_SEC_LEVEL_AUTHPRIV &&
                session.securityAuthProtoLen == 10 &&
                session.securityPrivProtoLen == 10 &&
                session.securityAuthKeyLen > 0 &&
                session.securityPrivKeyLen > 0;
            OKF(ok, ("v3 session credentials correct for %s", device));
        } else {
            snprintf(community, sizeof(community), "comm-%03d", i);
            ok = session.version == found->version &&
                session.community != NULL &&
                session.community_len == strlen(community) &&
                0 == strcmp((char *) session.community, community);
            OKF(ok, ("community session credentials correct for %s",
                     device));
        }
        SNMP_FREE(session.community);
        SNMP_FREE(session.securityName);
        SNMP_FREE(session.securityAuthProto);
        SNMP_FREE(session.securityPrivProto);
    }

    /*
     * Parse 100 deviceAuth configuration lines.
     */
    for (i = 0; i < NUM_DEVICES; i++) {
        if (0 == i % 2)
            snprintf(line, sizeof(line),
                     "confdev-%03d 2c community=pub-%03d", i, i);
        else
            snprintf(line, sizeof(line),
                     "confdev-%03d 3 secName=confuser-%03d "
                     "secLevel=authNoPriv authProto=MD5 authPass=pass-%03d",
                     i, i, i);
        rc = netsnmp_device_auth_parse_line(line);
        OKF(SNMPERR_SUCCESS == rc, ("parsed config line %d", i));
    }

    OKF(2 * NUM_DEVICES == netsnmp_device_auth_count(),
        ("registry holds %d devices after config parsing",
         2 * NUM_DEVICES));

    found = netsnmp_device_auth_find("confdev-001");
    ok = found != NULL && found->version == SNMP_VERSION_3 &&
        found->sec_name != NULL &&
        0 == strcmp(found->sec_name, "confuser-001") &&
        found->sec_level == SNMP_SEC_LEVEL_AUTHNOPRIV &&
        found->auth_proto != NULL && 0 == strcmp(found->auth_proto, "MD5");
    OK(ok, "parsed v3 config entry has expected fields");

    found = netsnmp_device_auth_find("confdev-000");
    ok = found != NULL && found->version == SNMP_VERSION_2c &&
        found->community != NULL && 0 == strcmp(found->community, "pub-000");
    OK(ok, "parsed v2c config entry has expected fields");

    /*
     * Error handling.
     */
    rc = netsnmp_device_auth_parse_line("baddev 9 community=x");
    OK(SNMPERR_BAD_VERSION == rc, "invalid version rejected");

    rc = netsnmp_device_auth_parse_line("baddev 2c");
    OK(SNMPERR_BAD_COMMUNITY == rc, "missing community rejected");

    rc = netsnmp_device_auth_parse_line("baddev 3");
    OK(SNMPERR_BAD_SEC_NAME == rc, "missing security name rejected");

    rc = netsnmp_device_auth_parse_line("baddev 1 community=x bogus=y");
    OK(SNMPERR_VALUE == rc, "unknown parameter rejected");

    OK(NULL == netsnmp_device_auth_find("nosuchdev"),
       "lookup of unknown device fails");

    snmp_sess_init(&session);
    rc = netsnmp_device_auth_setup_session(&session, "nosuchdev");
    OK(SNMPERR_BAD_NAME == rc, "setup_session of unknown device fails");

    /*
     * Replacement, removal and cleanup.
     */
    entry = netsnmp_device_auth_create("device-000", SNMP_VERSION_2c);
    entry->community = strdup("replaced");
    rc = netsnmp_device_auth_add(entry);
    found = netsnmp_device_auth_find("device-000");
    ok = SNMPERR_SUCCESS == rc && found != NULL &&
        found->version == SNMP_VERSION_2c &&
        0 == strcmp(found->community, "replaced");
    OK(ok, "re-adding a device replaces its entry");
    OK(2 * NUM_DEVICES == netsnmp_device_auth_count(),
       "replacement does not change device count");

    rc = netsnmp_device_auth_remove("device-000");
    OK(SNMPERR_SUCCESS == rc, "removed device-000");
    OK(NULL == netsnmp_device_auth_find("device-000"),
       "device-000 no longer registered");
    rc = netsnmp_device_auth_remove("device-000");
    OK(SNMPERR_BAD_NAME == rc, "removing unknown device fails");

    netsnmp_device_auth_clear();
    OK(0 == netsnmp_device_auth_count(), "registry cleared");
}
