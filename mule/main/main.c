/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include <stdio.h>
#include <inttypes.h>
#include <math.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"

// BLE headers
// TODO: non-volatile storage headers?
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "console/console.h"
#include "services/gap/ble_svc_gap.h"
#include "blecent.h"
#include "esp_central.h"

// mbedtls and/or crypto headers
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl_cookie.h"
#include "certs.h"
#include "time.h"

struct ble_hs_adv_fields;
struct ble_gap_conn_desc;
struct ble_hs_cfg;
union ble_store_value;
union ble_store_key;

// SENSOR_LAB11
// c0:98:e5:45:aa:bb
// 0x180A

#define NEBULA_SVC_UUID 0x180A // This is the UUID for the Nebula service

static const ble_uuid_t *sensor_svc_uuid = BLE_UUID128_DECLARE(
    0x70, 0x6C, 0x98, 0x41, 0xCE, 0x43, 0x14, 0xA9,
    0xB5, 0x4D, 0x22, 0x2B, 0x89, 0x10, 0xE6, 0x32
);

static const ble_uuid_t *sensor_chr_uuid = BLE_UUID128_DECLARE(
    0x70, 0x6C, 0x98, 0x41, 0xCE, 0x43, 0x14, 0xA9,
    0xB5, 0x4D, 0x22, 0x2B, 0x11, 0x89, 0xE6, 0x32
);

static const ble_uuid_t *metadata_chr_uuid = BLE_UUID128_DECLARE(
    0x70, 0x6C, 0x98, 0x41, 0xCE, 0x43, 0x14, 0xA9,
    0xB5, 0x4D, 0x22, 0x2B, 0x12, 0x89, 0xE6, 0x32
);

#define CHUNK_SIZE 200
#define MAX_PAYLOADS 10
#define READ_TIMEOUT_MS 1000
#define MAX_RETRY       5
#define SERVER_NAME "SENSOR_LAB11"

uint8_t sensor_state [CHUNK_SIZE];
uint8_t sensor_state_data [1500]; // for storing the data 
uint8_t sensor_state_str [1500]; //for storing the certs 
uint8_t metadata_state [3];

uint8_t big_data [10000];
uint8_t *payloads [MAX_PAYLOADS];
int num_payloads;


static const char *tag = "MULE_LAB11"; // The Mule is an ESP32 device
static int mule_ble_gap_event(struct ble_gap_event *event, void *arg);

uint16_t ble_conn_handle;
uint16_t metadata_attr_handle;
uint16_t sensor_attr_handle;

//Silly semaphore to signal when data has been written 
bool sema_metadata;
bool sema_data; 

void ble_store_config_init();

/*
* App call back for read of characteristic has completed
*/
static int ble_on_read(uint16_t conn_handle, const struct ble_gatt_error *error,
                        struct ble_gatt_attr *attr, void *arg) {
    
    MODLOG_DFLT(INFO, "Read complete; status=%d conn_handle=%d", error->status,conn_handle);
    if (error->status == 0) {
        MODLOG_DFLT(INFO, " attr_handle=%d value=", attr->handle);
        print_mbuf(attr->om);
    }
    MODLOG_DFLT(INFO, "\n");

    // put data into buffer depending on which characteristic was read
    if (attr->handle == metadata_attr_handle) {
        printf("Metadata recieved!\n");
        memcpy(metadata_state, attr->om->om_data, attr->om->om_len);
        sema_metadata = 1;
    } else if (attr->handle == sensor_attr_handle) {
        printf("Data recieved!\n");
        memcpy(sensor_state, attr->om->om_data, attr->om->om_len);
        sema_data = 1;
    }

    return 0; //TODO: should it sometimes return an error?
}

/*
* App call back for write of characteristic has completed
*/
static int ble_on_write(uint16_t conn_handle, const struct ble_gatt_error *error,
                        struct ble_gatt_attr *attr, void *arg) {

    MODLOG_DFLT(INFO,"Write complete; status=%d conn_handle=%d attr_handle=%d\n",
                error->status, conn_handle, attr->handle);
    return 0;
}

/*
* App call back for subscribe to data characteristic has completed
*/
static int ble_on_subscribe(uint16_t conn_handle, const struct ble_gatt_error *error,
                            struct ble_gatt_attr *attr, void *arg) {

    MODLOG_DFLT(INFO, "Subscribe data complete; status=%d conn_handle=%d attr_handle=%d\n",
                error->status, conn_handle, attr->handle);

    // write out MTU size to console 
    MODLOG_DFLT(INFO, "MTU size: %d\n", ble_att_mtu(conn_handle));
    return 0;
}


/*
* App call back for subscribe to metadata characteristic has completed
*/
static int ble_on_subscribe_meta(uint16_t conn_handle, const struct ble_gatt_error *error,
                            struct ble_gatt_attr *attr, void *arg) {

    MODLOG_DFLT(INFO, "Subscribe meta complete; status=%d conn_handle=%d attr_handle=%d\n",
                error->status, conn_handle, attr->handle);
    return 0;
}

static void ble_read(const struct peer *peer, struct peer_chr *chr) {   
    
    //const struct peer_chr *chr;
    int rc;

    /* Find the UUID. */

    //print the one we are looking for 
    //char chr_uuid_str[37];
    //char svc_uuid_str[37];
    //ble_uuid_to_str(sensor_svc_uuid, svc_uuid_str);
    //printf("service UUID: %s\n", svc_uuid_str);
    //ble_uuid_to_str(sensor_chr_uuid, chr_uuid_str);
    //printf("characteristic UUID: %s\n", chr_uuid_str);
    
    //chr =  peer_chr_find_uuid(peer, sensor_svc_uuid, sensor_chr_uuid);
    
    if (chr == NULL) {
        printf("Error: Peer doesn't support NEBULA\n");
    }

    /* Read the characteristic. */
    rc = ble_gattc_read(peer->conn_handle, chr->chr.val_handle,
                        ble_on_read, NULL);
    if (rc != 0) {
        printf("Error: Failed to read characteristic; rc=%d\n", rc);
    }
}

static void ble_write(const struct peer *peer, uint8_t *buf, const struct peer_chr *chr, size_t len) {

    //const struct peer_chr *chr;
    int rc;

    printf('in ble_write\n');
    
    /* Find the UUID. */
    // chr = peer_chr_find_uuid(peer, sensor_svc_uuid, chr);
    // if (chr == NULL) {
    //     printf("Error: Peer doesn't support NEBULA\n");
    // }

    //TODO: still need to output this error where chr is found 
    //printf("buf[0]%d\n", buf[0]);

    /* Write the characteristic. */
    rc = ble_gattc_write_flat(peer->conn_handle, chr->chr.val_handle,
                              buf, len, ble_on_write, NULL);
    if (rc != 0) {
        printf("Error: Failed to write characteristic; rc=%d\n", rc);
    }
}

static void ble_subscribe(const struct peer *peer) {

    //const struct peer_chr *chr;
    const struct peer_dsc *dsc;
    const struct peer_dsc *dsc_meta;
    uint8_t value[2];
    uint8_t value_meta[2];
    int rc;

    /* Find the UUID. */
    dsc = peer_dsc_find_uuid(peer, sensor_svc_uuid, sensor_chr_uuid,
                            BLE_UUID16_DECLARE(BLE_GATT_DSC_CLT_CFG_UUID16));
    if (dsc == NULL) {
        printf("Error: Peer doesn't support NEBULA\n");
    }

    /* Find the metadata UUID */
    dsc_meta = peer_dsc_find_uuid(peer, sensor_svc_uuid, metadata_chr_uuid,
                            BLE_UUID16_DECLARE(BLE_GATT_DSC_CLT_CFG_UUID16));

    if (dsc_meta == NULL) {
        printf("Error: Peer doesn't support NEBULA metadata\n");
    }

    sensor_attr_handle = dsc->dsc.handle;
    metadata_attr_handle = dsc_meta->dsc.handle;

    /* Subscribe to the characteristics. */
    value[0] = 1;
    value[1] = 0;
    rc = ble_gattc_write_flat(peer->conn_handle, dsc->dsc.handle,
                              value, sizeof(value), ble_on_subscribe, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error: Failed to subscribe to characteristic; "
                           "rc=%d\n", rc);
    }

    printf("subscribing to metadata\n");
    //delay 1 second
    vTaskDelay(1000 / portTICK_PERIOD_MS);

    value_meta[0] = 1;
    value_meta[1] = 0;
    rc = ble_gattc_write_flat(peer->conn_handle, dsc_meta->dsc.handle,
                              value_meta, sizeof(value_meta), ble_on_subscribe_meta, NULL);

    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error: Failed to subscribe to meta characteristic; "
                           "rc=%d\n", rc);
    }

    return;

}

int ble_write_long(void *p_ble_conn_handle, const unsigned char *buf, size_t len)
{
    // //wait for connection to be established
    // while (ble_gap_conn_active() == 0) {
    //     //wait  
    //     printf("waiting for BLE connection\n");
    //     vTaskDelay(1000 / portTICK_PERIOD_MS);
    // }

    //get peer from connection handle and peer chrs from uuids
    const struct peer *peer = peer_find(ble_conn_handle);
    const struct peer_chr *chr_metadata = peer_chr_find_uuid(peer, sensor_svc_uuid, metadata_chr_uuid);
    const struct peer_chr *chr_data = peer_chr_find_uuid(peer, sensor_svc_uuid, sensor_chr_uuid);

    //call ble_write to set metadata
    metadata_state[0] = ceil(len/(float)CHUNK_SIZE);
    metadata_state[1] = 0x00;
    ble_write(peer, metadata_state, chr_metadata, 2);

    //Send data packets in chunks
    int counter = 0; 
    int num_sent_packets = 0; 
    while (len >= CHUNK_SIZE) {
        int temp = counter + CHUNK_SIZE;
        ble_write(peer, &buf[counter], chr_data, CHUNK_SIZE);
        len = len - CHUNK_SIZE;
        counter = counter + CHUNK_SIZE;
        num_sent_packets += 1;

        //wait for ack to send next packet 
        //ble_read(peer, chr_metadata);
        while (metadata_state[1] != num_sent_packets) {
            printf("waiting for ack\n");
            printf("metadata state: %d\n", metadata_state[1]);
            // delay 1 second
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }

        printf("metadata state: %d\n", metadata_state[1]);

    }

    // Send remaining data 
    //ble_write(peer, &buf[counter], chr_data, len);

    //write complete put back in listening mode
    metadata_state[0] = 0;
    metadata_state[1] = 0;
    metadata_state[2] = 0;
    ble_write(peer, metadata_state, chr_metadata, 3);

    return len;
}


int ble_read_long(void *p_ble_conn_handle, unsigned char *buf, size_t len) 
{
    // //wait for connection to be established TODO??
    // while (ble_gap_conn_active() == 0) {
    //     //wait  
    //     printf("waiting for BLE connection\n");
    //     vTaskDelay(1000 / portTICK_PERIOD_MS);
    // }

    //get peer from connection handle and peer chrs from uuids 
    const struct peer *peer = peer_find(ble_conn_handle);
    const struct peer_chr *chr_metadata = peer_chr_find_uuid(peer, sensor_svc_uuid, metadata_chr_uuid);
    const struct peer_chr *chr_data = peer_chr_find_uuid(peer, sensor_svc_uuid, sensor_chr_uuid);

    // call ble_read to get metadata 
    ble_read(peer, chr_metadata);
    while (sema_metadata == 0) {
        //wait for callback to finish
    }
    //now the read data is in metadata_state
    int num_chunks = metadata_state[0]; 
    int num_recieved_chunks = metadata_state[1];

    //set the sema back to 0 since we are done with the metadata for now
    sema_metadata = 0;

    while (num_recieved_chunks < num_chunks) {
        //call ble_read to get the next data chunk 
        ble_read(peer, chr_data);
        while (sema_data == 0) {
            //wait for callback to finish
        }
        //now the read data is in sensor_state 
        memcpy(&buf[num_recieved_chunks*CHUNK_SIZE], sensor_state, CHUNK_SIZE);
        //set the sema back to 0 since we are done copying data 
        sema_data = 0;
    }

    //recieve the leftover data 
    ble_read(peer, chr_data);
    while (sema_data == 0) {
        //wait for callback to finish
    }
    //now the read data is in sensor_state
    memcpy(&buf[num_recieved_chunks*CHUNK_SIZE], sensor_state, len - num_recieved_chunks*CHUNK_SIZE);

    return len;
}


/**
 * Initiates the GAP general discovery procedure.
 */
static void
sensor_scan(void)
{
    uint8_t own_addr_type;
    struct ble_gap_disc_params disc_params;
    int rc;

    //Figure out address to use while advertising TODO: change this??
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "error determining address type; rc=%d\n", rc);
        return;
    }

    //Tell the controller to filter duplicates
    disc_params.filter_duplicates = 1;

    //Perform a passive scan
    disc_params.passive = 1;

    //Use defaults for the rest of the parameters. 
    disc_params.itvl = 0;
    disc_params.window = 0;
    disc_params.filter_policy = 0;
    disc_params.limited = 0;

    rc = ble_gap_disc(own_addr_type, 5000, &disc_params,
                      mule_ble_gap_event, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error initiating GAP discovery procedure; rc=%d\n",
                    rc);
    }
}

/**
 * Called when service discovery of the specified peer has completed.
 */
static void
ble_on_disc_complete(const struct peer *peer, int status, void *arg)
{

    if (status != 0) {
        /* Service discovery failed.  Terminate the connection. */
        MODLOG_DFLT(ERROR, "Error: Service discovery failed; status=%d "
                    "conn_handle=%d\n", status, peer->conn_handle);
        ble_gap_terminate(peer->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        return;
    }
    /* Service discovery has completed successfully.  Now we have a complete
     * list of services, characteristics, and descriptors that the peer
     * supports.
     */
    
    MODLOG_DFLT(INFO, "Service discovery complete; status=%d "
                "conn_handle=%d\n", status, peer->conn_handle);

    /* 
     * Now perform read
     */

    //ble_read(peer);
    //printf("read done\n");
    //ble_write(peer);
    //printf("write done\n");
    ble_subscribe(peer); 
    printf("subscribe done\n");
}

int
ble_uuid_u128(const ble_uuid_t *uuid)
{

    return uuid->type == BLE_UUID_TYPE_128 ? BLE_UUID128(uuid)->value : 0;
}


/**
 * Checks if the specified advertisement looks like a galaxy sensor.
**/
static int
sensor_should_connect(const struct ble_gap_disc_desc *disc)
{
    struct ble_hs_adv_fields fields;
    int rc;
    int i;

    /* The device has to be advertising connectability. */
    if (disc->event_type != BLE_HCI_ADV_RPT_EVTYPE_ADV_IND &&
            disc->event_type != BLE_HCI_ADV_RPT_EVTYPE_DIR_IND) {

        return 0;
    }

    /* Parse the advertisement data. */
    rc = ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data);
    if (rc != 0) {
        return rc;
    }

    //The device has to advertise support for Galaxy services (0x180a).
    for (i = 0; i < fields.num_uuids16; i++) {
        printf("uuid16 is=%x\n", ble_uuid_u16(&fields.uuids16[i].u));
        if (ble_uuid_u16(&fields.uuids16[i].u) == 0x180a) { //TODO fix this magic
            return 1;
        }
    }

    return 0;
}


/**
 * Connects to the sender of the specified advertisement of it looks
 * like a galaxy sensor.  A device is treated as a sensor if it advertises 
 * connectability and support for galaxy sensor service.
 */
static void
mule_connect_if_sensor(void *disc)
{
    uint8_t own_addr_type;
    int rc;
    ble_addr_t *addr;

    //Don't do anything if it is not a sensor 
    if (!sensor_should_connect((struct ble_gap_disc_desc *)disc)) {
        //printf("Not a sensor\n");
        return;
    }

    /* Scanning must be stopped before a connection can be initiated. */
    rc = ble_gap_disc_cancel();
    if (rc != 0) {
        MODLOG_DFLT(DEBUG, "Failed to cancel scan; rc=%d\n", rc);
        return;
    }

    //Figure out address to use for connect TODO: maybe remove this after mbedtls works??
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "error determining address type; rc=%d\n", rc);
        return;
    }

    //Try to connect the the advertiser.
    addr = &((struct ble_gap_disc_desc *)disc)->addr;

    rc = ble_gap_connect(own_addr_type, addr, 30000, NULL,
                         mule_ble_gap_event, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error: Failed to connect to device; addr_type=%d "
                    "addr=%s; rc=%d\n",
                    addr->type, addr_str(addr->val), rc);
        return;
    }
}

/**
 * The nimble host executes this callback when a GAP event occurs.  The
 * application associates a GAP event callback with each connection that is
 * established.  blecent uses the same callback for all connections.
 *
 * @param event                 The event being signalled.
 * @param arg                   Application-specified argument; unused by
 *                                  blecent.
 *
 * @return                      0 if the application successfully handled the
 *                                  event; nonzero on failure.  The semantics
 *                                  of the return code is specific to the
 *                                  particular GAP event being signalled.
 */
static int
mule_ble_gap_event(struct ble_gap_event *event, void *arg)
{
    struct ble_gap_conn_desc desc;
    struct ble_hs_adv_fields fields;
    int rc;

    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        rc = ble_hs_adv_parse_fields(&fields, event->disc.data,
                                     event->disc.length_data);
        if (rc != 0) {
            return 0;
        };

        //Try to connect to the advertiser if it looks like a galaxy sensor
        mule_connect_if_sensor(&event->disc);
        return 0;

    case BLE_GAP_EVENT_CONNECT:
        //A new connection was established or a connection attempt failed
        if (event->connect.status == 0) {
            //Connection successfully established
            MODLOG_DFLT(INFO, "Connection established ");

            rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
            assert(rc == 0);
            print_conn_desc(&desc);
            MODLOG_DFLT(INFO, "\n");

            //Remember peer
            rc = peer_add(event->connect.conn_handle);
            if (rc != 0) {
                MODLOG_DFLT(ERROR, "Failed to add peer; rc=%d\n", rc);
                return 0;
            }

            //Perform service discovery 
            rc = peer_disc_all(event->connect.conn_handle,
                        ble_on_disc_complete, NULL);
            if(rc != 0) {
                MODLOG_DFLT(ERROR, "Failed to discover services; rc=%d\n", rc);
                return 0;
            }

            //Save the connection handle for future reference
            ble_conn_handle = event->connect.conn_handle;

        } else {
            //Connection attempt failed; resume scanning
            MODLOG_DFLT(ERROR, "Error: Connection failed; status=%d\n",
                        event->connect.status);
            sensor_scan();
        }

        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        //Connection terminated
        MODLOG_DFLT(INFO, "disconnect; reason=%d ", event->disconnect.reason);
        print_conn_desc(&event->disconnect.conn);
        MODLOG_DFLT(INFO, "\n");

        //Forget about peer
        peer_delete(event->disconnect.conn.conn_handle);

        //Resume scanning
        sensor_scan();
        return 0;

    case BLE_GAP_EVENT_DISC_COMPLETE:
        MODLOG_DFLT(INFO, "discovery complete; reason=%d\n",
                    event->disc_complete.reason);
        return 0;

    // case BLE_GAP_EVENT_ENC_CHANGE:
    //     /* Encryption has been enabled or disabled for this connection. */
    //     MODLOG_DFLT(INFO, "encryption change event; status=%d ",
    //                 event->enc_change.status);
    //     rc = ble_gap_conn_find(event->enc_change.conn_handle, &desc);
    //     assert(rc == 0);
    //     print_conn_desc(&desc);
    //     return 0;

    case BLE_GAP_EVENT_NOTIFY_RX:
        /* Peer sent us a notification or indication. */
        MODLOG_DFLT(INFO, "received %s; conn_handle=%d attr_handle=%d "
                    "attr_len=%d; value=",
                    event->notify_rx.indication ?
                    "indication" :
                    "notification",
                    event->notify_rx.conn_handle,
                    event->notify_rx.attr_handle,
                    OS_MBUF_PKTLEN(event->notify_rx.om));
        
        print_mbuf(event->notify_rx.om);
        printf("\n");
 
        //if data is sensor state, update sensor state buffer and metadata buffer
        if (event->notify_rx.attr_handle == metadata_attr_handle -1 ) { //literally no clue why -1
            //update metadata buffer
            os_mbuf_copydata(event->notify_rx.om,0,OS_MBUF_PKTLEN(event->notify_rx.om),metadata_state);
            sema_metadata = 1;

        }
        else if (event->notify_rx.attr_handle == sensor_attr_handle - 1) { //literally no clue why -1
            //check metadata to find out where to put the data 
            int number_of_chunks = metadata_state[0];
            int number_recieved_chunks = metadata_state[1];
            int readiness = metadata_state[2];

            printf("number recieved chunks %d\n", number_recieved_chunks);
            
            //update sensor state buffer
            printf("len of recieved data: %d\n", event->notify_rx.om->om_len);
            os_mbuf_copydata(event->notify_rx.om,0,OS_MBUF_PKTLEN(event->notify_rx.om),&sensor_state_data[number_recieved_chunks*CHUNK_SIZE]);
            
            metadata_state[1] += 1; //adding a packet to the metadata
            sema_data = 1;
            sema_metadata = 1;

            printf("writing ack to sensor%d\n", metadata_state[1]);

            //write an ack to the sensor
            struct peer *peer = peer_find(event->notify_rx.conn_handle);
            struct peer_chr *chr = peer_chr_find_uuid(peer, sensor_svc_uuid, metadata_chr_uuid);
            ble_write(peer, metadata_state, chr, 3);
        }
        else {
            printf("unknown characteristic data\n");
        }

        printf("metadata total chunks: %d\n",metadata_state[0]);
        printf("metadata chunks recieved: %d\n",metadata_state[1]);
        printf("metadata readiness: %d\n",metadata_state[2]);

        
        return 0;

    case BLE_GAP_EVENT_MTU:
        MODLOG_DFLT(INFO, "mtu update event; conn_handle=%d cid=%d mtu=%d\n",
                    event->mtu.conn_handle,
                    event->mtu.channel_id,
                    event->mtu.value);
        return 0;

    // case BLE_GAP_EVENT_REPEAT_PAIRING:
    //     /* We already have a bond with the peer, but it is attempting to
    //      * establish a new secure link.  This app sacrifices security for
    //      * convenience: just throw away the old bond and accept the new link.
    //      */

    //     /* Delete the old bond. */
    //     rc = ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc);
    //     assert(rc == 0);
    //     ble_store_util_delete_peer(&desc.peer_id_addr);

    //     /* Return BLE_GAP_REPEAT_PAIRING_RETRY to indicate that the host should
    //      * continue with the pairing operation.
    //      */
    //     return BLE_GAP_REPEAT_PAIRING_RETRY;

    default:
        return 0;
    }
}


static void ble_on_reset(int reason) {
    MODLOG_DFLT(ERROR, "Resetting state; reason=%d\n", reason);
}

static void ble_on_sync(void) {
    int rc;

    /* Make sure we have proper identity address set (public preferred) */
    rc = ble_hs_util_ensure_addr(0);
    assert(rc == 0);

    /* Begin scanning for a peripheral to connect to. */
    sensor_scan();

}


void mbedtls_stuff() {
    printf("Starting the mbedtls client stuff\n");

    int ret, len;
    //mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers = "dtls_client";
    int retry_left = MAX_RETRY;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    //mbedtls_x509_crt cacert;
    mbedtls_timing_delay_context timer;

//     ((void) argc);
//     ((void) argv);

// #if defined(MBEDTLS_DEBUG_C)
//     mbedtls_debug_set_threshold(DEBUG_LEVEL);
// #endif

    /*
     * 0. Initialize the RNG and the session data
     */
    //mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    //mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_printf("\n  . Seeding the random number generator...");
    

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     NULL,
                                     0)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        
    }

    mbedtls_printf(" ok\n");

    //skip cert load and net connect stuff

    mbedtls_printf("  . Setting up the DTLS structure...");
    

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        
    }

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    //mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    //mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    mbedtls_ssl_conf_read_timeout(&conf, READ_TIMEOUT_MS);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        
    }

    // mbedtls_ssl_set_bio(&ssl, &server_fd,
    //                     mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    // mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
    //                          mbedtls_timing_get_delay);

    // mbedtls_printf(" ok\n");



    //int error_code;

    /*
    * Initialize the RNG and the session data
    */

    // initialize entropy and seed random generator
    // mbedtls_entropy_context entropy;
    // mbedtls_ctr_drbg_context ctr_drbg; 

    // mbedtls_entropy_init(&entropy);
    // mbedtls_ctr_drbg_init(&ctr_drbg);
    // if ((error_code = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
    //     printf("error at line %d: mbedtls_ctr_drbg_seed returned %d\n", __LINE__, error_code);
    //     abort();
    // }

    // // initialize TLS server parameters
    // mbedtls_x509_crt srvcert;
    // mbedtls_ssl_context ssl;
    // mbedtls_ssl_config conf;
    // mbedtls_pk_context pkey;
    // mbedtls_timing_delay_context timer; 
    // mbedtls_net_context listen_fd, client_fd;
    // mbedtls_ssl_cookie_ctx cookie_ctx;

    // mbedtls_net_init(&listen_fd);
    // mbedtls_net_init(&client_fd);
    // mbedtls_x509_crt_init(&srvcert);
    // mbedtls_ssl_init(&ssl);
    // mbedtls_ssl_config_init(&conf);
    // mbedtls_pk_init(&pkey);
    // mbedtls_ssl_cookie_init(&cookie_ctx);


    // /*
    // * Load the certificates and private RSA key
    // */
    
    // // Initialize server with mule certificate
    // const unsigned char *cert_data = mule_srv_crt;
    // error_code = mbedtls_x509_crt_parse(
    //     &srvcert,
    //     cert_data,
    //     mule_srv_crt_len
    // );
    // if (error_code) {
    //     printf("error at line %d: mbedtls_x509_crt_parse returned %d\n", __LINE__, error_code);
    //     abort();
    // }

    // const unsigned char *key_data = mule_srv_key;
    // error_code = mbedtls_pk_parse_key(
    //     &pkey,
    //     key_data,
    //     mule_srv_key_len, NULL, 0,
    //     mbedtls_ctr_drbg_random, &ctr_drbg
    // );
    // if (error_code) {
    //     printf("error at line %d: mbedtls_pk_parse_key returned %d\n", __LINE__, error_code);
    //     abort();
    // }
    
    // /*
    // * Setup SSL stuff
    // */
    
    // // Setup server
    // error_code = mbedtls_ssl_config_defaults(
    //     &conf,
    //     MBEDTLS_SSL_IS_SERVER,
    //     MBEDTLS_SSL_TRANSPORT_DATAGRAM, 
    //     MBEDTLS_SSL_PRESET_DEFAULT
    // );
    // if (error_code) {
    //     printf("error at line %d: mbedtls_ssl_config_defaults returned %d\n", __LINE__, error_code);
    //     abort();
    // }

    // mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    // //mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    // //mbedtls_ssl_conf_read_timeout(&conf, READ_TIMEOUT_MS);

    // mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    // error_code = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    // if (error_code) {
    //     printf("error at line %d: mbedtls_ssl_conf_own_cert returned %d\n", __LINE__, error_code);
    //     abort();
    // }
    
    // error_code = mbedtls_ssl_setup(&ssl, &conf);
    // if (error_code) {
    //     printf("error at line %d: mbedtls_ssl_setup returned %d\n", __LINE__, error_code);
    //     abort();
    // }

    //waits for BLE connection to continue 
    // while (ble_gap_conn_active() == 0) {
    //     //wait  
    //     printf("waiting for BLE connection\n");
    //     vTaskDelay(1000 / portTICK_PERIOD_MS);
    // }

    // Set bio to call ble connection
    mbedtls_ssl_set_bio(&ssl, ble_conn_handle, ble_write_long, ble_read_long, NULL);

    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                              mbedtls_timing_get_delay);

    // //Handshake 
    // ret = mbedtls_ssl_handshake(&ssl);
    // if (ret != 0) {
    //     printf("error at line %d: mbedtls_ssl_handshake returned %d\n", __LINE__, ret);
    //     char error_buf[100];
    //     mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    //     printf("SSL/TLS handshake error: %s\n", error_buf);
    //      //abort();
    // }
    // else {
    //     printf("mbedtls handshake successful\n");
    // }

    // while(true) {
    //     //wait for data
    //     vTaskDelay(1000 / portTICK_PERIOD_MS);
    // }

    // mbedtls_ssl_session_reset(&ssl);
    // // TODO call mbedtls_ssl_session_reset(&ssl) when new connection

    // printf("mbedtls done\n");


}

void mule_host_task(void *param)
{
    ESP_LOGI(tag, "BLE Host Task Started");
    /* This function will return only when nimble_port_stop() is executed */
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void app_main() {

    printf("Hello!\n");

    /* Print chip information */
    esp_chip_info_t chip_info;
    uint32_t flash_size;
    esp_chip_info(&chip_info);
    printf("This is %s chip with %d CPU core(s), WiFi%s%s%s, ",
           CONFIG_IDF_TARGET,
           chip_info.cores,
           (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
           (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "",
           (chip_info.features & CHIP_FEATURE_IEEE802154) ? ", 802.15.4 (Zigbee/Thread)" : "");

    unsigned major_rev = chip_info.revision / 100;
    unsigned minor_rev = chip_info.revision % 100;
    printf("silicon revision v%d.%d, ", major_rev, minor_rev);
    if(esp_flash_get_size(NULL, &flash_size) != ESP_OK) {
        printf("Get flash size failed");
        return;
    }

    printf("%" PRIu32 "MB %s flash\n", flash_size / (uint32_t)(1024 * 1024),
           (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

    printf("Minimum free heap size: %" PRIu32 " bytes\n", esp_get_minimum_free_heap_size());

    // Initialize NVS.
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    printf("nvs initialized\n");

    // Initialize the NimBLE host configuration.
    ret = nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(tag, "Failed to init nimble %d ", ret);
        return;
    }

    printf("nimble initialized\n");

    // Configure NimBLE host parameters
    ble_hs_cfg.reset_cb = ble_on_reset;
    ble_hs_cfg.sync_cb = ble_on_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    printf("host configured\n");

    //Init gatt and device name 
    int rc;

    rc = peer_init(MYNEWT_VAL(BLE_MAX_CONNECTIONS), 64, 64, 64);
    if (rc != 0) {
        ESP_LOGE(tag, "error initializing gatt server");
        return;
    }

    rc = ble_svc_gap_device_name_set("Lab11 Mule");
    if (rc != 0) {
        ESP_LOGE(tag, "error setting device name");
        return;
    }

    printf("peer configured and device name set\n");

    ble_store_config_init();

    //Start the muling task 
    nimble_port_freertos_init(mule_host_task);
    
    printf("started connection\n");

    while (true) {
        printf(".");
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }

    //mbedtls handshake
    //mbedtls_stuff();

    //set up packet pointers to beginning of big_data
    // for (int i = 0; i < MAX_PAYLOADS; i++) {
    //     payloads[i] = big_data;
    // }

    // num_payloads = 0; // initialize the number of payloads to 0, TODO magic number
    // while(num_payloads < 10) { // get data and send data to either server or back to sensor

    //     //waits for BLE connection to continue 
    //     // while (ble_gap_conn_active() == 0) {
    //     //     //wait  
    //     //     printf("waiting for BLE connection\n");
    //     //     vTaskDelay(1000 / portTICK_PERIOD_MS);
    //     // }

    //     //waiting for data transfer 
    //     if (metadata_state[2] != 2) {
    //         //printf("waiting for data transfer\n");
    //         //printf("metadata_state[2] = %d\n", metadata_state[2]);
    //         vTaskDelay(1000 / portTICK_PERIOD_MS);
    //         continue;
    //     }
    //     else {
    //         printf("data transfer complete\n");
    //         //copy to big buffer using payload pointers
    //         memcpy(payloads[num_payloads], sensor_state_data, CHUNK_SIZE*metadata_state[0]); 
    //         num_payloads++;

    //         // TODO: do we have data to write to the sensor?
    //         // TODO: is it time to upload our data? 
    //         // Go back to waiting for data transfer state
    //         vTaskDelay(1000 / portTICK_PERIOD_MS);
    //         metadata_state[0] = 0;
    //         metadata_state[1] = 0;
    //         metadata_state[2] = 0;
    //         ble_write_long(&ble_conn_handle, metadata_state, 3);
             
    //     }
    // }

    // //TODO: disconnect and wait to send data to server
    // printf("disconnect BLE\n");
    nimble_port_stop();

    



    //data transfer complete we can write data to server (or write back to sensor)
    //int len = 1000;
    //printf("sensor state data [0]%d\n", sensor_state_data[0]);
    //len = ble_write_long(&ble_conn_handle, sensor_state_data, len);



    //int len = 0;
    //uint8_t data_buf[1000];
    //len = ble_read_long(&ble_conn_handle, &data_buf, 1000);
    //len = ble_write_long(&ble_conn_handle, &data_buf, len);

    
    //get connection handle 

    //mbedtls_stuff();

    //TODO: clean up mbedtls stuff and restart 
    
    // for (int i = 30; i >= 0; i--) {
    //     printf("Restarting in %d seconds...\n", i);
    //     vTaskDelay(1000 / portTICK_PERIOD_MS);
    // }
    // printf("Restarting now.\n");
    // fflush(stdout);
    // esp_restart();
}
