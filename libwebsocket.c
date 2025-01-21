/*******************************************************************************
 * 
 * File Name: libwebsocket.c
 * 
 * Copyright (C) 2023 Microchip Technology Inc. and its subsidiaries.
 * Subject to your compliance with these terms, you may use Microchip software
 * and any derivatives exclusively with Microchip products. It is your
 * responsibility to comply with third party license terms applicable to your
 * use of third party software (including open source software) that may
 * accompany Microchip software.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *******************************************************************************/

#include "libwebsocket.h"
#include "utils.h"
#include "../ocpp16-manager/ocpp_process.h"
#include "../cjson/cJSON.h"

/* Cipher suites, https://www.openssl.org/docs/apps/ciphers.html */
static const char *const preferredCiphers = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";
//static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//static const char *const preferredCiphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDH-ECDSA-AES128-CBC-SHA256:ECDHE-ECDSA-AES128-CBC-SHA256";

//static const char *const preferredCiphers = "TLS-RSA-WITH-AES-128-GCM-SHA256:TLS-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:TLS-AES-256-GCM-SHA384:TLS-AES-128-GCM-SHA256:TLS-CHACHA20-POLY1305-SHA256";

//static const char * const preferredCiphers = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384";

/* Define errors */
static char *errors[] = {
    "Unknown error occured",
    "Error while getting address info",
    "Could connect to any address returned by getaddrinfo",
    "Error receiving data in client run thread",
    "Error during libwsclient_close",
    "Error sending while handling control frame",
    "Received masked frame from server",
    "Got null pointer during message dispatch",
    "Attempted to send after close frame was sent",
    "Attempted to send during connect",
    "Attempted to send null payload",
    "Attempted to send too much data",
    "Error during send in libwsclient_send",
    "Remote end closed connection during handshake",
    "Problem receiving data during handshake",
    "Remote web server responded with bad HTTP status during handshake",
    "Remote web server did not respond with upgrade header during handshake",
    "Remote web server did not respond with connection header during handshake",
    "Remote web server did not specify the appropriate Sec-WebSocket-Accept header during handshake",
    NULL
};

// Function to read the content of a file into a string
char *read_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        //perror("Error opening file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = (char *)malloc(length + 1);
    if (!content) {
        //perror("Error allocating memory");
        fclose(file);
        return NULL;
    }

    int bytesRead = fread(content, 1, length, file);
    if(bytesRead < 0)
    {
    	return NULL;
    }
    content[length] = '\0';

    fclose(file);
    return content;
}

// Function to extract the chargePointID value from the JSON file
char *get_chargePointID(const char *json_data) {
    cJSON *json = cJSONParse(json_data);
    if (!json) {
        //printf("Error parsing JSON: %s\n", cJSONGetErrorPtr());
        return NULL;
    }

    cJSON *development = cJSONGetObjectItemCaseSensitive(json, "development");
    if (development) {
        cJSON *id = cJSONGetObjectItemCaseSensitive(development, "chargePointID");
        if (cJSONIsString(id) && id->valuestring) {
            char *result = strdup(id->valuestring); // Duplicate the string to return
            cJSONDelete(json);
            return result;
        }
    }

    cJSONDelete(json);
    return NULL;
}

// Function to get the current timestamp as a string
void getCurrentTimestamp(char *timestamp, size_t size) {
    time_t now = time(NULL);
    struct tm *localTime = localtime(&now);
    strftime(timestamp, size, "%Y-%m-%d %H:%M:%S", localTime);
}

// Wrapper function to log messages to RxLogs.txt
void LOG_RX(const char *format, ...) {
    FILE *file;
    char timestamp[20];
    char logMessage[512];
    va_list args;

    // Open the file in append mode
    file = fopen("RxLogs.txt", "a");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Get the current timestamp
    getCurrentTimestamp(timestamp, sizeof(timestamp));

    // Format the log message
    va_start(args, format);
    vsnprintf(logMessage, sizeof(logMessage), format, args);
    va_end(args);

    // Write the timestamp and log message to the file
    fprintf(file, "[%s] %s\n", timestamp, logMessage);

    // Close the file
    fclose(file);
}

// Wrapper function to log messages to TxLogs.txt
void LOG_TX(const char *format, ...) {
    FILE *file;
    char timestamp[20];
    char logMessage[512];
    va_list args;

    // Open the file in append mode
    file = fopen("TxLogs.txt", "a");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Get the current timestamp
    getCurrentTimestamp(timestamp, sizeof(timestamp));

    // Format the log message
    va_start(args, format);
    vsnprintf(logMessage, sizeof(logMessage), format, args);
    va_end(args);

    // Write the timestamp and log message to the file
    fprintf(file, "[%s] %s\n", timestamp, logMessage);

    // Close the file
    fclose(file);
}
/**
 *   @brief   --> this function is the entry point for intiating websocket connection to server
 *   @param  --> const char *URI : This is the URL of Websocket server where connection is to be initiated
 */

WSCLIENT *LibWSClientNew(const char *URI)
{
    OCPPLogMessage(LOG_INFO, LOG_SENDING, "Inside libws client\n");
    /* Made ws_client */
    WSCLIENT *client = NULL;
    OCPPLogMessage(LOG_INFO, LOG_SENDING, "Completed the client connection\n");
    client = (WSCLIENT *)malloc(sizeof(WSCLIENT));
    if (!client)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Unable to allocate memory in LibWSClientNew.\n");
        exit(WS_EXIT_MALLOC);
    }
    (void)memset(client, 0, sizeof(WSCLIENT));
    if (pthread_mutex_init(&client->lock, NULL) != 0)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Unable to init mutex in LibWSClientNew.\n");
        exit(WS_EXIT_PTHREAD_MUTEX_INIT);
    }
    if (pthread_mutex_init(&client->send_lock, NULL) != 0)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Unable to init send lock in LibWSClientNew.\n");
        exit(WS_EXIT_PTHREAD_MUTEX_INIT);
    }
    pthread_mutex_lock(&client->lock);
    client->URI = (char *)malloc(strlen(URI) + 1U);
    if (!client->URI)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Unable to allocate memory in LibWSClientNew.\n");
        exit(WS_EXIT_MALLOC);
    }
    (void)memset(client->URI, 0, strlen(URI) + 1U);
    (void)strcpy(client->URI, URI);
    client->flags |= CLIENT_CONNECTING;
    pthread_mutex_unlock(&client->lock);

    client->stop_handshake_thread = 0;
    client->stop_thread = 0;

    /* Creating new thread which initiates handshake with the server */
    if (pthread_create(&client->handshake_thread, NULL, LibWSClientHandShakeThread, (void *)client))
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Unable to create handshake thread.\n");
        exit(WS_EXIT_PTHREAD_CREATE);
    }
    return client;
}

void LibWSClientStop(WSCLIENT *client)
{
    /* Lock mutex before modifying stop flags */
    pthread_mutex_lock(&client->lock);
    client->stop_handshake_thread = 1;
    client->stop_thread = 1;
    pthread_mutex_unlock(&client->lock);
    
    LibWSClientOnClose(client, NULL); /* Set the onclose callback to NULL */
    LibWSClientOnOpen(client, NULL);  /* Set the onopen callback to NULL */
    LibWSClientOnMessage(client, NULL); /* Set the onmessage callback to NULL */
    LibWSClientOnError(client, NULL);  /* Set the onerror callback to NULL */
    free(client);
}

static void InitOpensslLibrary(void)
{
    /* https://www.openssl.org/docs/ssl/SSL_library_init.html */
    (void)SSL_library_init();
    /* Cannot fail (always returns success) ??? */

    /* https://www.openssl.org/docs/crypto/ERR_load_crypto_strings.html */
    SSL_load_error_strings();
    /* Cannot fail ??? */

    /* SSL_load_error_strings loads both libssl and libcrypto strings */
    /* ERR_load_crypto_strings(); */
    /* Cannot fail ??? */

    /* OpenSSL_config may or may not be called internally, based on */
    /*  some #defines and internal gyrations. Explicitly call it    */
    /*  *IF* you need something from openssl.cfg, such as a         */
    /*  dynamically configured ENGINE.                              */
    /* OPENSSL_config(NULL);*/
    /* Initialization for OpenSSL 1.1.0 and later */
    OPENSSL_init_ssl(0, NULL);
    /* Cannot fail ??? */

    /* Include <openssl/opensslconf.h> to get this define     */
#if defined(OPENSSL_THREADS)
    /* TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO */
    /* https://www.openssl.org/docs/crypto/threads.html */
    (void)fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}

static int VerifyCallback(int preverify, X509_STORE_CTX *x509_ctx)
{
    (void)preverify;
    (void)x509_ctx;
	return 1;
}

/**
 *   @brief   -->  This function intiates the websocket connection with the server, it follows the process that is mentioned in rfc6455
 *   @param  -->  void *ptr : This is the pointer which points towards URI, that is passed while calling it
 */

void *LibWSClientHandShakeThread(void *ptr)
{
    OCPPLogMessage(LOG_INFO, LOG_SENDING, "Inside handshake thread\n");
    WSCLIENT *client = (WSCLIENT *)ptr;
    WSCLIENT_ERROR *err = NULL;
    const char *URI = client->URI;
    SHA1Context shactx;
    const char *UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char pre_encode[WS_PRE_ENCODE + UUID_SIZE];
    char sha1bytes[CISTRING_20TYPE_LENGTH];
    char expected_base64[WS_EXPECTED_BASE_LEN];
    char request_headers[1024];
    char websocket_key[WS_KEY_LENGTH ];
    char key_nonce[16];
    char scheme[10];
    char host[CISTRING_255TYPE_LENGTH];
    char request_host[CISTRING_255TYPE_LENGTH+CISTRING_20TYPE_LENGTH];
    char port[10];
    char path[CISTRING_255TYPE_LENGTH];
    char recv_buff[HELPER_RECV_BUF_SIZE ];
    char *URI_copy = NULL, *p = NULL, *rcv = NULL, *tok = NULL;
    int sockfd, n, flags = 0;
    char auth_header[512] = {0};
    int mtls = 0; // TODO: - Read SecurityProfile from DB and set to to 1 if profile 3.
    size_t z;
    unsigned int i;
    URI_copy = (char *)malloc(strlen(URI) + 1U);
    if (!URI_copy)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Unable to allocate memory in libwclient handshake.\n");
        exit(WS_EXIT_MALLOC);
    }
    /* Check if thread stop is requested before starting handshake */
    pthread_mutex_lock(&client->lock);
    if (client->stop_handshake_thread == 1)
    {
        pthread_mutex_unlock(&client->lock);
        OCPPLogMessage(LOG_INFO, LOG_SENDING, "Handshake thread stop requested, exiting.\n");
    	free(client);
    	free(URI_copy);
        pthread_exit(0); /* exit the thread signalling normal return */
        return NULL;
    }
    pthread_mutex_unlock(&client->lock);
    
    (void)memset(URI_copy, 0, strlen(URI) + 1U);
    OCPPLogMessage(LOG_INFO, LOG_SENDING, "URI: %s\n\r", URI);
    (void)strcpy(URI_copy, URI);
    OCPPLogMessage(LOG_INFO, LOG_SENDING, "URI_copy: %s\n\r", URI_copy);
    p = strstr(URI_copy, "://");
    if (p == NULL)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Malformed or missing scheme for URI.\n");
        exit(WS_EXIT_BAD_SCHEME);
    }
    (void)strncpy(scheme, URI_copy, p - URI_copy);
    scheme[p - URI_copy] = '\0';
    OCPPLogMessage(LOG_INFO, LOG_SENDING, "Scheme = %s\n", scheme);
    if ((strncmp(scheme, "ws", strlen(scheme)) != 0) && (strncmp(scheme, "wss", strlen(scheme)) != 0))
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Invalid scheme for URI: %s\n", scheme);
        exit(WS_EXIT_BAD_SCHEME);
    }

    if (strncmp(scheme, "ws", strlen(scheme)) == 0)
    {
        (void)strncpy(port, "8180", 9); /* server is at port 8180 --> Change this port to 80 when going to production */
    }
    else
    {
        (void)strncpy(port, HOST_PORT, 9);
        pthread_mutex_lock(&client->lock);
        client->flags |= CLIENT_IS_SSL;
        pthread_mutex_unlock(&client->lock);
        OCPPLogMessage(LOG_INFO, LOG_SENDING, "Secure Connection Required\n\r");
        OCPPLogMessage(LOG_INFO, LOG_SENDING, "Check for Client Flag: %d\n\r", client->flags);
    }
    for (i = p - URI_copy + 3, z = 0; *(URI_copy + i) != '/' && *(URI_copy + i) != ':' && *(URI_copy + i) != '\0'; i++, z++)
    {
        host[z] = *(URI_copy + i);
    }
    host[z] = '\0';
    if (*(URI_copy + i) == ':')
    {
        i++;
        p = strchr(URI_copy + i, '/');
        if (!p)
        {
            p = strchr(URI_copy + i, '\0');
        }
        (void)strncpy(port, URI_copy + i, (p - (URI_copy + i)));
        port[p - (URI_copy + i)] = '\0';
        i += p - (URI_copy + i);
    }
    if (*(URI_copy + i) == '\0')
    {
        /* end of URI request path will be */
        (void)strcpy(path, "/");
    }
    else
    {
        (void)strncpy(path, URI_copy + i, 254);
    }
    free(URI_copy);
    OCPPLogMessage(LOG_INFO, LOG_SENDING, "path = > %s\n", path);
    sockfd = LibWSClientOpenConnection(host, port); /* line 564 */

    if (sockfd < 0)
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(sockfd);
            client->onerror(client, err);
            free(err);
            err = NULL;
        }
        return NULL;
    }
#ifdef HAVE_LIBSSL

    if (((unsigned int)client->flags & CLIENT_IS_SSL) != 0U)
    {
        long res = 1;
        int result = 0;
        InitOpensslLibrary();
        OCPPLogMessage(LOG_INFO, LOG_SENDING, "SSL init done\n\r");

        /*if((libwsclient_flags & WS_FLAGS_SSL_INIT) == 0)
        {

            libwsclient_flags |= WS_FLAGS_SSL_INIT;
        }*/
        /* client->ssl_ctx = InitCTX();
         client->ssl_ctx = SSL_CTX_new(SSLv23_method());
         client->ssl = SSL_new(client->ssl_ctx);
        client->ssl = SSL_new(client->ssl_ctx);
        SSL_set_fd(client->ssl, sockfd);
        connect_ssl = SSL_connect(client->ssl);
        printf("Secure connection %ld\n\r",connect_ssl);
        if(connect_ssl == FAIL)
        {
            printf("SSL Connect failed\n\r");
        }*/

        /* https://www.openssl.org/docs/ssl/SSL_CTX_new.html */
        const SSL_METHOD *method = SSLv23_method();
        if (!(NULL != method))
        {
            OCPPLogMessage(LOG_ERROR, LOG_SENDING, "method error\n\r");
            /* return -1; */
        }
        /* http://www.openssl.org/docs/ssl/ctx_new.html */
        client->ssl_ctx = SSL_CTX_new(method);

        if (!(client->ssl_ctx != NULL))
        {
            OCPPLogMessage(LOG_ERROR, LOG_SENDING, "SSL CTX error\n\r");
            /* return -1; */
        }
        /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
        SSL_CTX_set_verify(client->ssl_ctx, SSL_VERIFY_PEER, VerifyCallback);
        /* Cannot fail ??? */

        /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
        SSL_CTX_set_verify_depth(client->ssl_ctx, 5);
        /* Cannot fail ??? */
        //

        /* Remove the most egregious. Because SSLv2 and SSLv3 have been      */
        /* removed, a TLSv1.0 handshake is used. The client accepts TLSv1.0  */
        /* and above. An added benefit of TLS 1.0 and above are TLS          */
        /* extensions like Server Name Indicatior (SNI).                     */
        flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
        long old_opts = SSL_CTX_set_options(client->ssl_ctx, flags);
        UNUSED(old_opts);
        /* http://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html */
        //TODO: Pass proper root CA cert here.
        res = SSL_CTX_load_verify_locations(client->ssl_ctx, "/etc/ssl/certs/ca-certificates.crt", NULL);
        if (!(1 == res))
        {
            /* Non-fatal, but something else will probably break later */
            OCPPLogMessage(LOG_WARN, LOG_SENDING, "SSL certificate location issue\n\r");
            /* break; */
        }
        client->ssl = SSL_new(client->ssl_ctx);
        SSL_set_fd(client->ssl, sockfd);
        if (mtls)
        {
            // Load the client certificate
            //TODO: Change client.pem to the proper client certificate.
            if (SSL_CTX_use_certificate_file(client->ssl_ctx, "client.pem", SSL_FILETYPE_PEM) <= 0)
            {
                printf("Error: Failed to load client certificate\n\r");
                return 0;
            }
            // Load the client private key
            // TODO: Change client.key to proper client key.
            if (SSL_CTX_use_PrivateKey_file(client->ssl_ctx, "client.key", SSL_FILETYPE_PEM) <= 0)
            {
                fprintf(stderr, "Error: Failed to load client private key\n");
                ERR_print_errors_fp(stderr);
                return 0;
            }
            // Verify that the private key matches the certificate
            if (!SSL_CTX_check_private_key(client->ssl_ctx))
            {
                printf("Error: Client private key does not match the certificate\n\r");
                return 0;
            }
            printf("mTLS enabled: client certificate and private key loaded successfully\n\r");
        }
        /* https://www.openssl.org/docs/ssl/ssl.html#DEALING_WITH_PROTOCOL_CONTEXTS */
        /* https://www.openssl.org/docs/ssl/SSL_CTX_set_cipher_list.html            */
        res = SSL_set_cipher_list(client->ssl, preferredCiphers);
        if (!(1 == res))
        {
            OCPPLogMessage(LOG_ERROR, LOG_SENDING, "SSL List Error\n\r");
            /* return 0; */
        }

        /* No documentation. See the source code for tls.h and s_client.c */
        res = SSL_set_tlsext_host_name(client->ssl, HOST_NAME);
        if (!(1 == res))
        {
            /* Non-fatal, but who knows what cert might be served by an SNI server  */
            /* (We know its the default site's cert in Apache and IIS...)           */
            OCPPLogMessage(LOG_ERROR, LOG_SENDING, "SSL host name error\n\r");
            /* break; */
        }

        result = SSL_connect(client->ssl);
        if (result == 1)
        {
            OCPPLogMessage(LOG_INFO, LOG_SENDING, "Socket SSL is done\n\r");
        }
        else
        {
            return 0;
        }
    }
    else
    {
        OCPPLogMessage(LOG_INFO, LOG_SENDING, "CHeck for Client Flag: %d\n\r", client->flags);
    }
#endif

    OCPPLogMessage(LOG_INFO, LOG_SENDING, "Socket Connected \n");

    pthread_mutex_lock(&client->lock);
    client->sockfd = sockfd;
    pthread_mutex_unlock(&client->lock);

    /* generate NONCE for Handshake */
    (void)GetNonce((uint8_t *)key_nonce, sizeof(key_nonce));
    (void)Base64Encode(key_nonce, sizeof(key_nonce), websocket_key, sizeof(websocket_key)); /* encoding the Nonce with base64 */

    (void)memset(request_headers, 0, 1024);

    if (strncmp(port, "80", strlen(port)) != 0)
    {
        (void)snprintf(request_host, (CISTRING_255TYPE_LENGTH + CISTRING_20TYPE_LENGTH), "%s:%s", host, port); /*Host length + port Length*/
    }
    else
    {
        (void)snprintf(request_host, CISTRING_255TYPE_LENGTH, "%s", host);
    }
    /* For OCPP connection always remember to put Sec-WebSocket-Protocol */
    /*
        GET /webServices/ocpp/CP3211 HTTP/1.1
        Host: some.server.com:33033
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
        Sec-WebSocket-Protocol: ocpp1.6, ocpp1.5
        Sec-WebSocket-Version: 13
    */
    //(void)snprintf(request_headers, 1024, "GET %s HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: ocpp1.6\r\nHost: %s\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, request_host, websocket_key);
    snprintf(
        request_headers, 1024,
        "GET %s HTTP/1.1\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Protocol: ocpp1.6\r\n"
        "Host: %s\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n",
        path, request_host, websocket_key);
    // TODO: Check SecurityProfile and check if profile 1 or profile 2 add:
    if (1)
    {
        char auth_encoded[512];

        const char *filename = "config.json";

        // Read the JSON file
        char *json_data = read_file(filename);
        if (!json_data) {
        	return NULL;
        }

        // Get the chargePointID
        char *username = get_chargePointID(json_data);
        if (username) {
        	printf("chargePointID: %s\n", username);
        	//free(chargePointID); // Free the duplicated string
        } else {
        	printf("chargePointID not found or not a string.\n");
        	return NULL;
        }

        free(json_data);
        char password[MAX_USER_NAME_PASSWORD_SZ] = "\0";

        FILE *file;
        char file_contents[1024];  // Buffer for file contents
        file = fopen("passwordDB", "r");
        if (file == NULL) {
        	file = fopen("passwordDB", "w");
        	if (file) {
        		fprintf(file, "%s", "test1234"); // Write default password into the file
        		//fclose(file);
        		//printf("File '%s' did not exist. Created and wrote default password inside.\n", password_filename);
        	} else {
        		//printf("Error: Could not create file '%s'.\n", password_filename);
        		//fclose(file);
        		return NULL; // Return an error code
        	}
        }

        if (fgets(file_contents, sizeof(file_contents), file) == NULL) {
        	perror("Error reading from passwordDB");
        	fclose(file);
        	return NULL;
        }
        snprintf(password, MAX_USER_NAME_PASSWORD_SZ, "%.39s", file_contents);
        // Close the file after reading
        fclose(file);

        OCPPLogMessage(LOG_INFO, LOG_SENDING, "User Name = %s\n", username);
        OCPPLogMessage(LOG_INFO, LOG_SENDING, "Password = %s\n", password);
        snprintf(auth_encoded, sizeof(auth_encoded), "%s:%s", username, password);
        Base64Encode(auth_encoded, strlen(auth_encoded), auth_header, sizeof(auth_header));
        snprintf(
            request_headers + strlen(request_headers), sizeof(request_headers) - strlen(request_headers),
            "Authorization: Basic %s\r\n", auth_header);
        free(username);
    }

    strcat(request_headers, "\r\n");    
    OCPPLogMessage(LOG_INFO, LOG_SENDING, "Request header = %s", request_headers);
    n = LibWSClientWrite(client, request_headers, strlen(request_headers));
    z = 0;

    (void)memset(recv_buff, 0, 1024);

    /* TODO: actually handle data after \r\n\r\n in case server */
    /* sends post-handshake data that gets coalesced in this recv */
    do
    {
        n = LibWSClientRead(client, recv_buff + z, (size_t)1023 - z);
        z += (size_t)n;
    } while ((z < (size_t)4 || strstr(recv_buff, "\r\n\r\n") == NULL) && n > 0);

    if (n == 0)
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(WS_HANDSHAKE_REMOTE_CLOSED_ERR);
            client->onerror(client, err);
            free(err);
            err = NULL;
        }
        return NULL;
    }
    if (n < 0)
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(WS_HANDSHAKE_RECV_ERR);
            err->extra_code = n;
            client->onerror(client, err);
            free(err);
        }
        return NULL;
    }

    /* parse recv_buf for response headers and assure Accept matches expected value */
    rcv = (char *)malloc(strlen(recv_buff) + 1U);
    if (!rcv)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Unable to allocate memory in LibWSClientNew.\n");
        exit(WS_EXIT_MALLOC);
    }
    (void)memset(rcv, 0, strlen(recv_buff) + 1U);
    (void)strcpy(rcv, recv_buff);
    (void)memset(pre_encode, 0,WS_PRE_ENCODE);
    (void)snprintf(pre_encode, WS_PRE_ENCODE + UUID_SIZE, "%s%s", websocket_key, UUID);
    SHA1Reset(&shactx);
    SHA1Input(&shactx, (const unsigned char *)pre_encode, strlen(pre_encode));
    (void)SHA1Result(&shactx);
    (void)memset(pre_encode, 0, WS_PRE_ENCODE);
    (void)snprintf(pre_encode, WS_PRE_ENCODE, "%08x%08x%08x%08x%08x", shactx.messageDigest[0], shactx.messageDigest[1], shactx.messageDigest[2], shactx.messageDigest[3], shactx.messageDigest[4]);
    for (z = 0; z < (strlen(pre_encode) / (size_t)2); z++)
    {
        (void)sscanf(pre_encode + (z * (size_t)2), "%02hhx", (unsigned char *)sha1bytes);
    }
    (void)memset(expected_base64, 0, WS_EXPECTED_BASE_LEN);
    (void)Base64Encode(sha1bytes, CISTRING_20TYPE_LENGTH , expected_base64,WS_EXPECTED_BASE_LEN );
    for (tok = strtok(rcv, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n"))
    {
        if (*tok == 'H' && *(tok + 1) == 'T' && *(tok + 2) == 'T' && *(tok + 3) == 'P')
        {
            p = strchr(tok, ' ');
            p = strchr(p + 1, ' ');
            *p = '\0';
            if (strncmp(tok, "HTTP/1.1 101", strlen(tok)) != 0 && strncmp(tok, "HTTP/1.0 101", strlen(tok)) != 0)
            {
                if (client->onerror != NULL)
                {
                    err = LibWSClientNewError(WS_HANDSHAKE_BAD_STATUS_ERR);
                    client->onerror(client, err);
                    free(err);
                    err = NULL;
                }
                return NULL;
            }
            flags |= REQUEST_VALID_STATUS;
        }
        else
        {
            p = strchr(tok, ' ');
            *p = '\0';
            if (strncmp(tok, "Upgrade:", strlen(tok)) == 0)
            {
                if (strcasecmp(p + 1, "websocket") == 0)
                {
                    flags |= REQUEST_HAS_UPGRADE;
                }
            }
            if (strncmp(tok, "Connection:", strlen(tok)) == 0)
            {
                if (strcasecmp(p + 1, "upgrade") == 0)
                {
                    flags |= REQUEST_HAS_CONNECTION;
                }
            }
            if (strncmp(tok, "Sec-WebSocket-Accept:", strlen(tok)) == 0)
            {
                if (strncmp(p + 1, expected_base64, strlen(p + 1)) == 0)
                {
                    flags |= REQUEST_VALID_ACCEPT;
                }
            }
        }
    }

    if (!((unsigned int)flags & REQUEST_HAS_UPGRADE))
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(WS_HANDSHAKE_NO_UPGRADE_ERR);
            client->onerror(client, err);
            free(err);
            err = NULL;
        }
        return NULL;
    }
    if (!((unsigned int)flags & REQUEST_HAS_CONNECTION))
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(WS_HANDSHAKE_NO_CONNECTION_ERR);
            client->onerror(client, err);
            free(err);
            err = NULL;
        }
        return NULL;
    }
    if (!((unsigned int)flags & REQUEST_VALID_ACCEPT))
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(WS_HANDSHAKE_BAD_ACCEPT_ERR);
            client->onerror(client, err);
            free(err);
            err = NULL;
        }
        return NULL;
    }

    pthread_mutex_lock(&client->lock);
    client->flags &= ~CLIENT_CONNECTING;
    pthread_mutex_unlock(&client->lock);
    if (client->onopen != NULL)
    {
        client->onopen(client);
    }
    return NULL;
}

/**
 *   @brief   --> This function opens the connection between client and server
 *   @param  --> const char *host : socket host which will be parsed from URI passed in the beginning
 *                const char *port : port address for socket connection
 */

int LibWSClientOpenConnection(const char *host, const char *port)
{
    struct addrinfo hints, *servinfo, *p;
    int rv, sockfd;
    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0)
    {
        return WS_OPEN_CONNECTION_ADDRINFO_ERR;
    }

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            continue;
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo);
    if (p == NULL)
    {
        return WS_OPEN_CONNECTION_ADDRINFO_EXHAUSTED_ERR;
    }
    return sockfd;
}

/**
 *   @brief   -->  function sets errorCode with error when ever any error occurs
 *   @param  -->  int errcode : error code to be passed
 */

WSCLIENT_ERROR *LibWSClientNewError(int errcode)
{
    WSCLIENT_ERROR *err = NULL;
    err = (WSCLIENT_ERROR *)malloc(sizeof(WSCLIENT_ERROR));
    if (!err)
    {
        /* one of the few places we will fail and exit */
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Unable to allocate memory in LibWSClientNewError.\n");
        exit(errcode);
    }
    (void)memset(err, 0, sizeof(WSCLIENT_ERROR));
    err->code = errcode;
    switch (err->code)
    {
        case WS_OPEN_CONNECTION_ADDRINFO_ERR:
            err->str = *(errors + 1);
            break;
        case WS_OPEN_CONNECTION_ADDRINFO_EXHAUSTED_ERR:
            err->str = *(errors + 2);
            break;
        case WS_RUN_THREAD_RECV_ERR:
            err->str = *(errors + 3);
            break;
        case WS_DO_CLOSE_SEND_ERR:
            err->str = *(errors + 4);
            break;
        case WS_HANDLE_CTL_FRAME_SEND_ERR:
            err->str = *(errors + 5);
            break;
        case WS_COMPLETE_FRAME_MASKED_ERR:
            err->str = *(errors + 6);
            break;
        case WS_DISPATCH_MESSAGE_NULL_PTR_ERR:
            err->str = *(errors + 7);
            break;
        case WS_SEND_AFTER_CLOSE_FRAME_ERR:
            err->str = *(errors + 8);
            break;
        case WS_SEND_DURING_CONNECT_ERR:
            err->str = *(errors + 9);
            break;
        case WS_SEND_NULL_DATA_ERR:
            err->str = *(errors + 10);
            break;
        case WS_SEND_DATA_TOO_LARGE_ERR:
            err->str = *(errors + 11);
            break;
        case WS_SEND_SEND_ERR:
            err->str = *(errors + 12);
            break;
        case WS_HANDSHAKE_REMOTE_CLOSED_ERR:
            err->str = *(errors + 13);
            break;
        case WS_HANDSHAKE_RECV_ERR:
            err->str = *(errors + 14);
            break;
        case WS_HANDSHAKE_BAD_STATUS_ERR:
            err->str = *(errors + 15);
            break;
        case WS_HANDSHAKE_NO_UPGRADE_ERR:
            err->str = *(errors + 16);
            break;
        case WS_HANDSHAKE_NO_CONNECTION_ERR:
            err->str = *(errors + 17);
            break;
        case WS_HANDSHAKE_BAD_ACCEPT_ERR:
            err->str = *(errors + 18);
            break;
        default:
            err->str = *errors;
            break;
    }

    return err;
}

/**
 *   @brief   -->  To send data from client to server
 *   @param  -->  WSCLIENT *client : websocket client struct
 *                 char *strdata    : data that is to be send to server of char * datatype
 */

int LibWSClientSend(WSCLIENT *client, char *strdata)
{
    WSCLIENT_ERROR *err = NULL;
    struct timeval tv;
    unsigned char mask[4];
    unsigned int mask_int;
    unsigned long long payload_len;
    unsigned char finNopcode;
    unsigned int payload_len_small;
    unsigned int payload_offset = 6;
    unsigned int len_size;
    unsigned int sent = 0;
    ssize_t i;
    unsigned int j;
    unsigned long frame_size;
    char *data;

    if (((unsigned int)client->flags & CLIENT_SENT_CLOSE_FRAME) != 0U)
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(WS_SEND_AFTER_CLOSE_FRAME_ERR);
            client->onerror(client, err);
            free(err);
            err = NULL;
        }
        return 0;
    }
    if (((unsigned int)client->flags & CLIENT_CONNECTING) != 0)
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(WS_SEND_DURING_CONNECT_ERR);
            client->onerror(client, err);
            free(err);
            err = NULL;
        }
        return 0;
    }
    if (strdata == NULL)
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(WS_SEND_NULL_DATA_ERR);
            client->onerror(client, err);
            free(err);
            err = NULL;
        }
        return 0;
    }

    gettimeofday(&tv, NULL);
    srand(tv.tv_usec * tv.tv_sec);
    mask_int = rand();
    (void)memcpy(mask, &mask_int, 4);
    payload_len = strlen(strdata);
    finNopcode = 0x81; /* FIN and text opcode. */
    if (payload_len <= 125U)
    {
        frame_size = 6U + payload_len;
        payload_len_small = payload_len;
    }
    else if (payload_len > 125U && payload_len <= 0xffffU)
    {
        frame_size = 8U + payload_len;
        payload_len_small = 126U;
        payload_offset += 2U;
    }
    else if ((payload_len > 0xFFFFU) && (payload_len <= (unsigned long long)INT64_MAX))
    {
        frame_size = 14U + payload_len;
        payload_len_small = 127U;
        payload_offset += 8U;
    }
    else
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(WS_SEND_DATA_TOO_LARGE_ERR);
            client->onerror(client, err);
            free(err);
            err = NULL;
        }
        return -1;
    }
    data = (char *)malloc(frame_size);
    (void)memset(data, 0, frame_size);
    *data = finNopcode;
    *(data + 1) = payload_len_small | 0x80U; /* payload length with mask bit on */
    if (payload_len_small == 126U)
    {
        payload_len &= 0xffff;
        len_size = 2;
        for (j = 0; j < len_size; j++)
        {
            *(data + 2U + j) = *((char *)&payload_len + (len_size - j - 1U));
        }
    }
    if (payload_len_small == 127U)
    {
        payload_len &= 0xffffffffffffffffULL;
        len_size = 8;
        for (j = 0; j < len_size; j++)
        {
            *(data + 2U + j) = *((char *)&payload_len + (len_size - j - 1U));
        }
    }
    for (j = 0U; j < 4U; j++)
    {
        *(data + (payload_offset - 4U) + j) = mask[j];
    }

    (void)memcpy(data + payload_offset, strdata, strlen(strdata));
    for (j = 0; j < strlen(strdata); j++)
    {
        *(data + payload_offset + j) ^= mask[j % 4U] & 0xffU;
    }
    sent = 0;
    i = 0;

    pthread_mutex_lock(&client->send_lock);
    while (sent < frame_size && i >= 0)
    {
        i = LibWSClientWrite(client, data + sent, frame_size - sent);
        sent += (unsigned int)i;
    }
    pthread_mutex_unlock(&client->send_lock);

    if (i < 0)
    {
        if (client->onerror != NULL)
        {
            err = LibWSClientNewError(WS_SEND_SEND_ERR);
            client->onerror(client, err);
            free(err);
            err = NULL;
        }
    }

    free(data);
    return sent;
}

/**
 *   @brief   -->  This function maintains running of websocket thread
 *   @param  -->  wsclient *c : Websocket client from stuct
 */

void LibWSClientRun(WSCLIENT *c)
{
    if (((unsigned int)c->flags & CLIENT_CONNECTING) != 0U)
    {
        pthread_join(c->handshake_thread, NULL);
        pthread_mutex_lock(&c->lock);
        c->flags &= ~CLIENT_CONNECTING;
        free(c->URI);
        c->URI = NULL;
        pthread_mutex_unlock(&c->lock);
    }
    if (c->sockfd != 0)
    {
        (void)pthread_create(&c->run_thread, NULL, LibWSClientRunThread, (void *)c);
    }
}

/**
 *   @brief  -->  This function is called when LibWSClientRun is called
 *   @param  -->  void *ptr : It is used for pointing towards websocket client
 */

void *LibWSClientRunThread(void *ptr)
{
    WSCLIENT *c = (WSCLIENT *)ptr;
    WSCLIENT_ERROR *err = NULL;
    char buf[HELPER_RECV_BUF_SIZE];
    int n, i;
    if (c->stop_thread == 1)
    {
        if (c->onclose != NULL)
        {
            c->onclose(c);
        }
        close(c->sockfd);
        free(c);
        pthread_exit(0); /* exit the thread signalling normal return */
        return NULL;
    }
    do
    {
        (void)memset(buf, 0, HELPER_RECV_BUF_SIZE);
        n = LibWSClientRead(c, buf, HELPER_RECV_BUF_SIZE);
        for (i = 0; i < n; i++)
        {
            LibWSClientInData(c, buf[i]);
        }

        LOG_RX("%s",buf);
    } while (n > 0);

    if (n < 0)
    {
        if (c->onerror != NULL)
        {
            err = LibWSClientNewError(WS_RUN_THREAD_RECV_ERR);
            err->extra_code = n;
            c->onerror(c, err);
            free(err);
            err = NULL;
        }
    }

    if (c->onclose != NULL)
    {
        c->onclose(c);
    }
    close(c->sockfd);
    return NULL;
}

/**
 *   @brief   -->  If any data comes from Websocket it is handled here
 *   @param  -->  wsclient *c : Websocket client
 *                 char in : Char type data coming in
 */

inline void LibWSClientInData(WSCLIENT *c, char in)
{
    WSCLIENT_FRAME *current = NULL, *new = NULL;
    pthread_mutex_lock(&c->lock);
    if (c->current_frame == NULL)
    {
        c->current_frame = (WSCLIENT_FRAME *)malloc(sizeof(WSCLIENT_FRAME));
        (void)memset(c->current_frame, 0, sizeof(WSCLIENT_FRAME));
        c->current_frame->payload_len = -1;
        c->current_frame->rawdata_sz = (unsigned int)FRAME_CHUNK_LENGTH;
        c->current_frame->rawdata = (char *)malloc(c->current_frame->rawdata_sz);
        (void)memset(c->current_frame->rawdata, 0, c->current_frame->rawdata_sz);
    }
    current = c->current_frame;
    if (current->rawdata_idx >= current->rawdata_sz)
    {
        current->rawdata_sz += (unsigned int)FRAME_CHUNK_LENGTH;
        current->rawdata = (char *)realloc(current->rawdata, current->rawdata_sz);
        (void)memset(current->rawdata + current->rawdata_idx, 0, current->rawdata_sz - current->rawdata_idx);
    }
    *(current->rawdata + current->rawdata_idx++) = in;
    pthread_mutex_unlock(&c->lock);
    if (LibWSClientCompleteFrame(c, current) == 1)
    {
        if (current->fin == 1U)
        {
            /* is control frame */
            if ((current->opcode & 0x08U) == 0x08U)
            {
                LibWSClientHandleControlFrame(c, current);
            }
            else
            {
                LibWSClientDispatchMessage(c, current);
                c->current_frame = NULL;
            }
        }
        else
        {
            new = (WSCLIENT_FRAME *)malloc(sizeof(WSCLIENT_FRAME));
            (void)memset(new, 0, sizeof(WSCLIENT_FRAME));
            new->payload_len = -1;
            new->rawdata = (char *)malloc(FRAME_CHUNK_LENGTH);
            (void)memset(new->rawdata, 0, FRAME_CHUNK_LENGTH);
            new->prev_frame = current;
            current->next_frame = new;
            c->current_frame = new;
        }
    }
}

/**
 *   @brief  -->  this function forms the complete frame for websocket
 *   @param  -->  WSCLIENT *c           : websocket client
 *                 WSCLIENT_FRAME *frame : websocket client frame
 */

int LibWSClientCompleteFrame(WSCLIENT *c, WSCLIENT_FRAME *frame)
{
    WSCLIENT_ERROR *err = NULL;
    int payload_len_short, i;
    unsigned long long payload_len = 0;
    if (frame->rawdata_idx < 2U)
    {
        return 0;
    }
    frame->fin = (*(frame->rawdata) & 0x80U) == 0x80U ? 1U : 0U;
    frame->opcode = *(frame->rawdata) & 0x0f;
    frame->payload_offset = 2;
    if ((*(frame->rawdata + 1) & 0x80) != 0x0)
    {
        if (c->onerror != NULL)
        {
            err = LibWSClientNewError(WS_COMPLETE_FRAME_MASKED_ERR);
            c->onerror(c, err);
            free(err);
            err = NULL;
        }
        pthread_mutex_lock(&c->lock);
        c->flags |= CLIENT_SHOULD_CLOSE;
        pthread_mutex_unlock(&c->lock);
        return 0;
    }
    payload_len_short = *(frame->rawdata + 1) & 0x7f;
    switch (payload_len_short)
    {
        case 126:
            if (frame->rawdata_idx < 4U)
            {
                return 0;
            }
            for (i = 0; i < 2; i++)
            {
                (void)memcpy((void *)&payload_len + i, frame->rawdata + 3 - i, 1);
            }
            frame->payload_offset += 2U;
            frame->payload_len = payload_len;
            break;
        case 127:
            if (frame->rawdata_idx < 10U)
            {
                return 0;
            }
            for (i = 0; i < 8; i++)
            {
                (void)memcpy((void *)&payload_len + i, frame->rawdata + 9 - i, 1);
            }
            frame->payload_offset += 8U;
            frame->payload_len = payload_len;
            break;
        default:
            frame->payload_len = payload_len_short;
            break;
    }
    if (frame->rawdata_idx < frame->payload_offset + frame->payload_len)
    {
        return 0;
    }
    return 1;
}

/**
 *   @brief  -->  This function controls the complete frame of websocket client
 *   @param  -->  WSCLIENT *c               : websocket client
 *                WSCLIENT_FRAME *ctl_frame : websocket control frame
 */

void LibWSClientHandleControlFrame(WSCLIENT *c, WSCLIENT_FRAME *ctl_frame)
{
    WSCLIENT_ERROR *err = NULL;
    WSCLIENT_FRAME *ptr = NULL;
    char mask[4];
    int mask_int;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand(tv.tv_sec * tv.tv_usec);
    mask_int = rand();
    (void)memcpy(mask, &mask_int, 4);
    pthread_mutex_lock(&c->lock);
    switch (ctl_frame->opcode)
    {
    case 0x8:
        /* close frame */
        if (((unsigned int)c->flags & CLIENT_SENT_CLOSE_FRAME) == 0U)
        {
            unsigned long long i; ssize_t n = 0;
            /* server request close.  Send close frame as acknowledgement. */
            for (i = 0; i < ctl_frame->payload_len; i++)
            {
                *(ctl_frame->rawdata + ctl_frame->payload_offset + i) ^= (mask[i % 4U] & 0xffU); /* mask payload */
            }
            *(ctl_frame->rawdata + 1) |= 0x80;                                                 /* turn mask bit on */
            i = 0;
            pthread_mutex_lock(&c->send_lock);
            while (i < ctl_frame->payload_offset + ctl_frame->payload_len && n >= 0)
            {
                n = LibWSClientWrite(c, ctl_frame->rawdata + i, ctl_frame->payload_offset + ctl_frame->payload_len - i);
                i += (unsigned long long)n;
            }
            pthread_mutex_unlock(&c->send_lock);
            if (n < 0)
            {
                if (c->onerror != NULL)
                {
                    err = LibWSClientNewError(WS_HANDLE_CTL_FRAME_SEND_ERR);
                    err->extra_code = n;
                    c->onerror(c, err);
                    free(err);
                    err = NULL;
                }
            }
        }
        c->flags |= CLIENT_SHOULD_CLOSE;
        break;
    case 0x09:
    {
        /*
            length of msg: 4
            Data: 89047069   ----------

        */
        uint8_t tp;
        OCPPLogMessage(LOG_INFO, LOG_SENDING, "PING Message Received\n\r");
        OCPPLogMessage(LOG_INFO, LOG_SENDING, "length of msg: %d\n\r", ctl_frame->payload_len);
        OCPPLogMessage(LOG_INFO, LOG_SENDING, "Data: ");
        for (tp = 0; tp < ctl_frame->payload_len; tp++)
        {
            OCPPLogMessage(LOG_INFO, LOG_SENDING, "%02X", ctl_frame->rawdata[tp]);
        }
        OCPPLogMessage(LOG_INFO, LOG_SENDING, "   ----------\n\r");
        break;
    }
    default:
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Unhandled control frame received.  Opcode: %d\n", ctl_frame->opcode);
        break;
    }

    ptr = ctl_frame->prev_frame; /* This very well may be a NULL pointer, but just in case we preserve it. */
    free(ctl_frame->rawdata);
    (void)memset(ctl_frame, 0, sizeof(WSCLIENT_FRAME));
    ctl_frame->prev_frame = ptr;
    ctl_frame->rawdata = (char *)malloc(FRAME_CHUNK_LENGTH);
    (void)memset(ctl_frame->rawdata, 0, FRAME_CHUNK_LENGTH);
    pthread_mutex_unlock(&c->lock);
}

/**
 *   @brief  -->  This function dispatches the message from client to server
 *   @param  -->  WSCLIENT *c             : websocket client
 *                WSCLIENT_FRAME *current : current frame for ws_client
 */

void LibWSClientDispatchMessage(WSCLIENT *c, WSCLIENT_FRAME *current)
{
    unsigned long long message_payload_len, message_offset;
    int message_opcode;
    char *message_payload;
    WSCLIENT_FRAME *first = NULL;
    WSCLIENT_MESSAGE *msg = NULL;
    WSCLIENT_ERROR *err = NULL;
    if (current == NULL)
    {
        if (c->onerror != NULL)
        {
            err = LibWSClientNewError(WS_DISPATCH_MESSAGE_NULL_PTR_ERR);
            c->onerror(c, err);
            free(err);
            err = NULL;
        }
        return;
    }
    message_offset = 0;
    message_payload_len = current->payload_len;
    for (; current->prev_frame != NULL; current = current->prev_frame)
    {
        message_payload_len += current->payload_len;
    }
    first = current;
    message_opcode = current->opcode;
    message_payload = (char *)malloc(message_payload_len + 1U);
    (void)memset(message_payload, 0, message_payload_len + 1U);
    for (; current != NULL; current = current->next_frame)
    {
        (void)memcpy(message_payload + message_offset, current->rawdata + current->payload_offset, current->payload_len);
        message_offset += current->payload_len;
    }

    LibWSClientCleanUpFrames(first);
    msg = (WSCLIENT_MESSAGE *)malloc(sizeof(WSCLIENT_MESSAGE));
    (void)memset(msg, 0, sizeof(WSCLIENT_MESSAGE));
    msg->opcode = message_opcode;
    msg->payload_len = message_offset;
    msg->payload = message_payload;
    if (c->onmessage != NULL)
    {
        c->onmessage(c, msg);
    }
    else
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "No onmessage call back registered with libwsclient.\n");
    }
    free(msg->payload);
    free(msg);
}

/**
 *   @brief   -->  once the connection is closed, this function cleans up the frames
 *   @param  -->  wsclient_frame _first : ws_client_frame which was used for the first time
 */

void LibWSClientCleanUpFrames(WSCLIENT_FRAME *first)
{
    WSCLIENT_FRAME *this = NULL;
    WSCLIENT_FRAME *next = first;
    while (next != NULL)
    {
        this = next;
        next = this->next_frame;
        if (this->rawdata != NULL)
        {
            free(this->rawdata);
        }
        free(this);
    }
}

/**
 *   @brief  -->  sends the data to socket
 *   @param  -->  WSCLIENT *c     : websocket client
 *                const void *buf : buffer size to be sent
 *                size_t length   : length of the buffer size
 */

ssize_t LibWSClientWrite(WSCLIENT *c, const void *buf, size_t length)
{
	LOG_TX("%s",(const char *)buf);
#ifdef HAVE_LIBSSL
    if (((unsigned int)c->flags & CLIENT_IS_SSL) != 0U)
    {
        return (ssize_t)SSL_write(c->ssl, buf, length);
    }
    else
    {
#endif
        return send(c->sockfd, buf, length, 0);
#ifdef HAVE_LIBSSL
    }
#endif

    /* return send(c->sockfd, buf, length, 0); */
}

/**
 *   @brief  -->  this reads the message received from socket
 *   @param  -->  WSCLIENT *c   : websocket client
 *                void *buf     : buffer to be used for storing data of no datatype
 *                size_t length : length of the buffer of message sent
 */

ssize_t LibWSClientRead(WSCLIENT *c, void *buf, size_t length)
{

#ifdef HAVE_LIBSSL
    if (((unsigned int)c->flags & CLIENT_IS_SSL) != 0U)
    {
        return (ssize_t)SSL_read(c->ssl, buf, length);
    }
    else
    {
#endif
        return recv(c->sockfd, buf, length, 0);
#ifdef HAVE_LIBSSL
    }
#endif

    /* return recv(c->sockfd, buf, length, 0); */
}

/**
 *   @brief  -->  this function kills the thread running
 *   @param  -->  WSCLIENT *client : websocket client
 */

void LibWSClientFinish(WSCLIENT *client)
{
    if (client->helper_thread)
    {
        pthread_kill(client->helper_thread, SIGINT);
    }
    if (client->run_thread)
    {
        pthread_join(client->run_thread, NULL);
    }
}

/**
 *   @brief  -->  this function closes the locked thread
 *   @param  -->  WSCLIENT *client        :  websocket client
 *                int (*cb)(WSCLIENT *c)  :  websocket call back function
 */

void LibWSClientOnClose(WSCLIENT *client, int (*cb)(WSCLIENT *c))
{
    pthread_mutex_lock(&client->lock);
    client->onclose = cb;
    pthread_mutex_unlock(&client->lock);
}

/**
 *   @brief  -->  this function opens the locked thread
 *   @param  -->  WSCLIENT *client        :  websocket client
 *                int (*cb)(WSCLIENT *c)  :  websocket call back function
 */

void LibWSClientOnOpen(WSCLIENT *client, int (*cb)(WSCLIENT *c))
{
    pthread_mutex_lock(&client->lock);
    client->onopen = cb;
    pthread_mutex_unlock(&client->lock);
}
/**
 *   @brief  -->  this function handle the message on the locked thread
 *   @param  -->  WSCLIENT *client        :  websocket client
 *                int (*cb)(WSCLIENT *c)  :  websocket call back function
 */

void LibWSClientOnMessage(WSCLIENT *client, int (*cb)(WSCLIENT *c, WSCLIENT_MESSAGE *msg))
{
    pthread_mutex_lock(&client->lock);
    client->onmessage = cb;
    pthread_mutex_unlock(&client->lock);
}
/**
 *   @brief  -->  this function handle the error on the locked thread
 *   @param  -->  WSCLIENT *client        :  websocket client
 *                int (*cb)(WSCLIENT *c)  :  websocket call back function
 */

void LibWSClientOnError(WSCLIENT *client, int (*cb)(WSCLIENT *c, WSCLIENT_ERROR *err))
{
    pthread_mutex_lock(&client->lock);
    client->onerror = cb;
    pthread_mutex_unlock(&client->lock);
}
