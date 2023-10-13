/*
 * Galaxy test app with BLE and Crypto enabled
 */

#include <stdbool.h>
#include <stdint.h>
#include <math.h>
#include "app_timer.h"
#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_uart.h"
#include "nrf_gpio.h"
#include "nrf_log.h"
#include "nrf_crypto.h"
#include "nrf_crypto_error.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
#include "nrf_drv_rng.h"
#include "nrf_drv_timer.h"
#include "simple_ble.h"
//#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include "ble_advertising.h"
#include "ble_conn_state.h"
#include "ble.h"
#include "certs.h"
#include "data.h"


// Pin definitions
#define LED NRF_GPIO_PIN_MAP(0,13)
#define CHUNK_SIZE 200
#define READ_TIMEOUT_MS 10000   /* 10 seconds */

// Intervals for advertising and connections
static simple_ble_config_t ble_config = {
        // c0:98:e5:45:aa:bb
        .platform_id       = 0x42,    // used as 4th octect in device BLE address
        .device_id         = 0xAABB,
        .adv_name          = "SENSOR_LAB11", // used in advertisements if there is room
        .adv_interval      = MSEC_TO_UNITS(1000, UNIT_0_625_MS),
        .min_conn_interval = MSEC_TO_UNITS(500, UNIT_1_25_MS),
        .max_conn_interval = MSEC_TO_UNITS(1000, UNIT_1_25_MS),
};

//Set up BLE service and characteristic for connection with ESP 
static simple_ble_service_t sensor_service = {{
    .uuid128 = {0x70,0x6C,0x98,0x41,0xCE,0x43,0x14,0xA9,
                0xB5,0x4D,0x22,0x2B,0x89,0x10,0xE6,0x32}
}};

static simple_ble_char_t sensor_state_char = {.uuid16 = 0x8911};

uint8_t sensor_state [CHUNK_SIZE]; //largest possible packet need to send chunks for larger

//Set up BLE characteristic for metadata connection with ESP

static simple_ble_char_t metadata_state_char = {.uuid16 = 0x8912};

uint8_t metadata_state [3]; // [0] = number of chunks to send, [1] = chunks recieved

simple_ble_app_t* simple_ble_app;

uint8_t *read_buf;

APP_TIMER_DEF(dtls_int_timer_id);
APP_TIMER_DEF(dtls_fin_timer_id);

// Prototype functions
int ble_write(uint16_t *buf, uint16_t len, simple_ble_char_t *characteristic, int offset);

int logging_init() {
    ret_code_t error_code = NRF_SUCCESS;
    error_code = NRF_LOG_INIT(NULL);
    //APP_ERROR_CHECK(error_code);
    NRF_LOG_DEFAULT_BACKENDS_INIT();
    return error_code;
}

int entropy_source(void *data, unsigned char *output, size_t len, size_t *olen)
{
    //Call TRNG peripheral:
    nrf_drv_rng_block_rand(output, len);
    *olen = len;

    // Return 0 on success
    return 0;
}

void ble_evt_write(ble_evt_t const * p_ble_evt) { 
    // Check if the event if on the link for this central
    if (p_ble_evt->evt.gatts_evt.conn_handle != simple_ble_app->conn_handle) {
        return;
    }
    
    //Check if data is metadata or data and store in correct variable
    if (p_ble_evt->evt.gatts_evt.params.write.handle == metadata_state_char.char_handle.value_handle) {
        printf("Metadata recieved!\n");
        memcpy(metadata_state, p_ble_evt->evt.gatts_evt.params.write.data, p_ble_evt->evt.gatts_evt.params.write.len);
    } 
    if (p_ble_evt->evt.gatts_evt.params.write.handle == sensor_state_char.char_handle.value_handle) {
        printf("Data recieved!\n");
        //check metadata to see where to store data and store data 
        int num_chunks = metadata_state[0];
        int num_recieved_chunks = metadata_state[1];
        int readiness = metadata_state[2];
        memcpy(&read_buf[num_recieved_chunks*CHUNK_SIZE], p_ble_evt->evt.gatts_evt.params.write.data, p_ble_evt->evt.gatts_evt.params.write.len);
        //increment metadata state since we recieved a chunk
        metadata_state[1] +=1;
        int error_code = ble_write(metadata_state, 3, &metadata_state_char, 0);
    }
 
}

int ble_write_long(void *p_ble_conn_handle, const unsigned char *buf, size_t len) 
{
    int error_code = 0;
    int original_len = len;
    uint16_t len_for_write = (uint16_t)len;

    //check we're in a connection
    if (simple_ble_app->conn_handle == BLE_CONN_HANDLE_INVALID) {
        printf("not connected can't write\n");
        return -1;
    }

    //now we can read and write the metadata state 
    if (metadata_state[2] != 0x00) {
        printf("ESP32 is not ready to receive data\n");
        return -1;
    }
    
    //write metadata test 
    printf("writing metadata[0]%d\n", metadata_state[0]);

    metadata_state[0] = ceil(len/(float)CHUNK_SIZE); //number of full packets to send
    metadata_state[1] = 0x00;
    metadata_state[2] = 0x01;
    error_code = ble_write(metadata_state, 3, &metadata_state_char, 0);

    //Now that sensor has a lock with metadata 
    //Send data packets in chunks of 510 bytes
    //TODO: change to for loop on both sensor and esp32 side
    int counter = 0;
    int num_sent_packets = 0;
    while (len_for_write >= CHUNK_SIZE) {
        int temp = counter + CHUNK_SIZE;
        error_code = ble_write(&buf[counter],CHUNK_SIZE, &sensor_state_char, 0);
        len_for_write -= CHUNK_SIZE;
        counter = counter + CHUNK_SIZE;
        num_sent_packets += 1;

        //wait for ack to send next packet
        while (metadata_state[1] != num_sent_packets) {
            printf("waiting for ack\n");
            printf("metadata state: %d\n", metadata_state[1]);
            printf("num sent packets: %d\n", num_sent_packets);
            nrf_delay_ms(500);
        }

        printf("number sent packets: %d\n", metadata_state[1]);
    }

    //wait for final ack from sensor
    while (metadata_state[1] != num_sent_packets) {
        printf("waiting for final ack\n");
        nrf_delay_ms(500);
    }

    //set metadata state to signal that we are done sending data
    metadata_state[1] = 0;
    metadata_state[2] = 0x02;

    error_code = ble_write(metadata_state, 3, &metadata_state_char, 0);

    return len;
}

int ble_read_long(void *p_ble_conn_handle, unsigned char *buf, size_t len) 
{
    //Check metadata state
    int error_code;
    int num_chunks = metadata_state[0];
    int num_recieved_chunks = metadata_state[1];
    int readiness = metadata_state[2];

    read_buf = buf; //set global read_buf to buf so we can access it in the callback

    // // Wait for metadata to signifiy we are ready to read
    // while (readiness != 0x02) {
    //     printf("not ready to read\n");
    //     nrf_delay_ms(500);
    // } TODO: put this back and fix metadata state perhaps 

    while (metadata_state[1] < metadata_state[0]) {
        nrf_delay_ms(500);
    }

    read_buf = NULL;
    return len;
 
}

// Function to send data over BLE
int ble_write(uint16_t *buf, uint16_t len, simple_ble_char_t *characteristic, int offset)
{
    // Check if BLE connection handle is valid
    if (simple_ble_app->conn_handle == BLE_CONN_HANDLE_INVALID) {
        printf("BLE connection handle is invalid!\n");
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }

    // Check connection status 
    int ret_code;
    ret_code = ble_conn_state_status(simple_ble_app->conn_handle);
    while (ret_code != BLE_CONN_STATUS_CONNECTED) {
        printf("Connection status: %d", ret_code);
        nrf_delay_ms(1000);
        ret_code = ble_conn_state_status(simple_ble_app->conn_handle);
    }

    ble_gatts_hvx_params_t hvx_params;
    memset(&hvx_params, 0, sizeof(hvx_params));
    hvx_params.handle = characteristic->char_handle.value_handle;
    hvx_params.type = BLE_GATT_HVX_NOTIFICATION;
    hvx_params.offset = offset;
    hvx_params.p_len = &len;
    hvx_params.p_data = buf;

    ret_code = sd_ble_gatts_hvx(simple_ble_app->conn_handle, &hvx_params);
    while (ret_code == NRF_ERROR_INVALID_STATE) {
        printf("Error writing try again\n");
        nrf_delay_ms(1000);
        ret_code = sd_ble_gatts_hvx(simple_ble_app->conn_handle, &hvx_params);
    }

    return ret_code;

}


// Function to receive data over BLE
int ble_read(simple_ble_char_t *characteristic)
{
    int ret_code;
    // Check if BLE connection handle is valid
    if (simple_ble_app->conn_handle == BLE_CONN_HANDLE_INVALID) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }

    // Check connection status 
    ret_code = ble_conn_state_status(simple_ble_app->conn_handle);
    while (ret_code == NRF_ERROR_BUSY) {
        printf("Connection status: %d", ret_code);
        nrf_delay_ms(1000);
        ret_code = ble_conn_state_status(simple_ble_app->conn_handle);
    }

    ret_code = sd_ble_gattc_read(simple_ble_app->conn_handle, characteristic->char_handle.value_handle, 0);
    while (ret_code != NRF_SUCCESS) {
        printf("Error reading try again\n");
        ret_code = sd_ble_gattc_read(simple_ble_app->conn_handle, characteristic->char_handle.value_handle, 0);
        nrf_delay_ms(1000);
    }
    
    return ret_code;
}

void data_test(uint16_t ble_conn_handle)
{
    printf("read and write data testing\n");
    int error_code;
    uint8_t data_buf [1000];
    uint8_t data_back [1000];
    //chill state to start with
    metadata_state[0] = 0x00;
    metadata_state[1] = 0x00;
    metadata_state[2] = 0x00; 

    //make random data 1kB
    for (int i = 0; i < 1000; i++) {
        data_buf[i] = 0x01; // rand() % 256;
    }
    printf("data_back address: %d\n", data_back);
    error_code = ble_write_long(&ble_conn_handle, data_buf, 1000);
    error_code = ble_read_long(&ble_conn_handle, data_back, 1000);

    printf("data sent and received, checking for errors\n");
    for (int i = 0; i < 1000; i++) {
        if (data_buf[i] != data_back[i]) {
            printf("error\n");
            printf("data_buf[%d] = %d\n", i, data_buf[i]);
            printf("data_back[%d] = %d\n", i, data_back[i]);
            continue;
        }
    }
}

struct dtls_delay_ctx {
    uint32_t int_ms;
    uint32_t fin_ms;
    bool int_timer_expired;
    bool fin_timer_expired;
};
static struct dtls_delay_ctx delay_ctx;

static void dtls_int_timer_handler(void * p_context) {
    struct dtls_delay_ctx *ctx = (struct dtls_delay_ctx *) p_context;
    ctx->int_timer_expired = true;
}

static void dtls_fin_timer_handler(void * p_context) {
    struct dtls_delay_ctx *ctx = (struct dtls_delay_ctx *) p_context;
    ctx->fin_timer_expired = true;
}

void dtls_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms) {

    struct dtls_delay_ctx *ctx = (struct dtls_delay_ctx *) data;
    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;
    ctx->int_timer_expired = false;
    ctx->fin_timer_expired = false;

    ret_code_t error_code = app_timer_stop_all();
    APP_ERROR_CHECK(error_code);

    // don't restart timers if we don't have a delay
    if (int_ms == 0 && fin_ms == 0) {
        return;
    }

    error_code = app_timer_start(dtls_int_timer_id, APP_TIMER_TICKS(int_ms), data);
    APP_ERROR_CHECK(error_code);

    error_code = app_timer_start(dtls_fin_timer_id, APP_TIMER_TICKS(fin_ms), data);
    APP_ERROR_CHECK(error_code);
}

int dtls_get_delay(void *data) {

    struct dtls_delay_ctx *ctx = (struct dtls_delay_ctx *) data;
    if (ctx->fin_ms == 0) {
        return -1;
    }

    if (ctx->fin_timer_expired) {
        return 2;
    }

    if (ctx->int_timer_expired) {
        return 1;
    }

    return 0; 
}

int main(void) {

    //setup error code
    ret_code_t error_code = NRF_SUCCESS;

    // Logging initialization
    error_code = logging_init();

    // Crypto initialization
    error_code = nrf_crypto_init();

    // put simple BLE up here so we can piggy-back on the app timer initialization
    simple_ble_app = simple_ble_init(&ble_config);

    error_code = app_timer_create(&dtls_int_timer_id, APP_TIMER_MODE_SINGLE_SHOT, dtls_int_timer_handler);
    APP_ERROR_CHECK(error_code);

    error_code = app_timer_create(&dtls_fin_timer_id, APP_TIMER_MODE_SINGLE_SHOT, dtls_fin_timer_handler);
    APP_ERROR_CHECK(error_code);

    //error_code = app_timer_start(dtls_int_timer_id, APP_TIMER_TICKS(1000), NULL);
    //APP_ERROR_CHECK(error_code);

    // mbedTLS initialization

    int ret, len;
    mbedtls_net_context server_fd;
    unsigned char buf[1024];
    const char *pers = 'dtls_server'; 
    unsigned char client_ip[16] = { 0 };
    size_t cliip_len;
    mbedtls_ssl_cookie_ctx cookie_ctx;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
    //mbedtls_timing_delay_context timer;


    // mbedtls_net_init(&listen_fd);
    // mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_cookie_init(&cookie_ctx);

    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    /*
     * 1. Seed the RNG
     */

    //Initialize the RNG and entropy source for mbedtls
    nrf_drv_rng_config_t rng_config = NRF_DRV_RNG_DEFAULT_CONFIG;
    error_code = nrf_drv_rng_init(&rng_config);

    error_code = mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                             MBEDTLS_ENTROPY_MAX_GATHER, MBEDTLS_ENTROPY_SOURCE_STRONG);


    printf("  . Seeding the random number generator...");

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     NULL,
                                     0)) != 0) {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        
    }

    printf(" ok\n");

    /*
     * 2. Load the certificates and private RSA key
     */
    printf("Loading the server cert. and key...\n");

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    const unsigned char *cert_data = sensor_cli_crt; //TODO: change name to sensor_svr_crt
    ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) cert_data,
                                 sensor_cli_crt_len);
    if (ret != 0) {
        printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
       
    }

    // ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_cas_pem,
    //                              mbedtls_test_cas_pem_len);
    // if (ret != 0) {
    //     printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
    //     goto exit;
    // } //TODO might need a CA certificate but ignore for now

    const unsigned char *key_data = sensor_cli_key;
    ret =  mbedtls_pk_parse_key(&pkey,
                                (const unsigned char *) key_data,
                                sensor_cli_key_len,
                                NULL,
                                0,
                                mbedtls_ctr_drbg_random,
                                &ctr_drbg);
    if (ret != 0) {
        printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        
    }

    printf(" ok\n");

    //TODO: I skipped setting up the listening UDP port since it's not needed in BLE dTLS

    /*
     * 4. Setup stuff
     */
    printf("  . Setting up the DTLS data...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    //mbedtls_ssl_conf_dbg(&conf, my_debug, stdout); TODO: might need a my_debug function
    mbedtls_ssl_conf_read_timeout(&conf, READ_TIMEOUT_MS);

    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        
    }

    if ((ret = mbedtls_ssl_cookie_setup(&cookie_ctx,
                                        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        printf(" failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret);
        
    }

    mbedtls_ssl_conf_dtls_cookies(&conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                                  &cookie_ctx);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        
    }

    mbedtls_ssl_set_timer_cb(&ssl, &delay_ctx, dtls_set_delay, dtls_get_delay);

    printf(" ok\n");

    //reset: TODO???

    mbedtls_ssl_session_reset(&ssl);

    //TODO: I skipped the wait until a client connects and client ID cause that's not needed

    
    /*
    * GPIO initialization
    */
    nrf_gpio_cfg_output(LED);

    /*
    * BLE initialization
    */

    simple_ble_add_service(&sensor_service);
 
    simple_ble_add_characteristic(1, 1, 1, 1,
        sizeof(sensor_state), (char*)&sensor_state,
        &sensor_service, &sensor_state_char);

    simple_ble_add_characteristic(1, 1, 1, 1,
        sizeof(metadata_state), (char*)&metadata_state,
        &sensor_service, &metadata_state_char);

    // Start Advertising
    advertising_start();

    //Wait for connection
    uint16_t ble_conn_handle = simple_ble_app->conn_handle;

    while (ble_conn_state_status(ble_conn_handle) != BLE_CONN_STATUS_CONNECTED) {
        printf("waiting to connect..\n");
        nrf_delay_ms(1000);
        ble_conn_handle = simple_ble_app->conn_handle;
    }

    printf("BLE connected, start mbedtls handshake\n");

    /*
    * MBEDTLS handshake
    */

    
    //Set bio to call ble connection TODO: 
    //mbedtls_ssl_set_bio(&ssl, ble_conn_handle, ble_write_long, ble_read_long, NULL );

    // // handshake
    // ret = mbedtls_ssl_handshake(&ssl);
    // // while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
    // //         ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    // if( ret != 0 )
    // {
    //     mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -ret );
    //     char error_buf[100];
    //     mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    //     printf("SSL/TLS handshake error: %s\n", error_buf);
    //     //abort();
    // }
    // else {
    //     printf("mbedtls handshake successful\n");
    // }


    //TODO: actually send data over mbedtls

    //stop ourselves from continuing on 
    // while(true) {
    //     nrf_delay_ms(1000);
    // }

    //Read and write test
    //data_test(ble_conn_handle);

    //End-to-End test
    while(true) {

        while (ble_conn_state_status(ble_conn_handle) != BLE_CONN_STATUS_CONNECTED) {
            printf("waiting to connect..\n");
            nrf_delay_ms(1000);
            ble_conn_handle = simple_ble_app->conn_handle;
        }

        if (metadata_state[2] == 2 ) {
            printf("waiting for mule to send data back\n");
            nrf_delay_ms(5000); // give em 5 seconds
            metadata_state[0] = 0;
            metadata_state[1] = 0;
            metadata_state[2] = 0;
            error_code = ble_write(metadata_state, 3, &metadata_state_char, 0);
        }
        else if (metadata_state[2] == 1) {
            //already sending data
        }
        else {
            // time to send some more data //todo make sensor state data
            printf("time to send more!\n");
            uint8_t data_test [1000];
            error_code = ble_write_long(&ble_conn_handle, data, 1000);
            printf("made it through sending data\n");
            nrf_delay_ms(10000);

        }
    }

 
    
    // Enter main loop.
    // printf("main loop starting\n");
    // int loop_counter = 0;
    // while (loop_counter < 10) {
    //     nrf_gpio_pin_toggle(LED);
    //     nrf_delay_ms(1000);
    //     printf("beep!\n");
    // }

    printf("done sending data, closing connection\n");

    // TODO: after mbedtls Cleanup 
    // printf("clean up!\n");
    // mbedtls_ecdh_free(&ctx_sensor);
    // //mbedtls_ecdh_free(&ctx_mule);
    // mbedtls_ctr_drbg_free(&ctr_drbg);
    // mbedtls_entropy_free(&entropy);
}


