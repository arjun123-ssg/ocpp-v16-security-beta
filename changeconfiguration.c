/******************************************************************************
 *
 * File: changeconfiguration.c
 *
 * Copyright (C) 2023 Microchip Technology Inc. and its subsidiaries.
 * Subject to your compliance with these terms, you may use Microchip software
 * and any derivatives exclusively with Microchip products. It is your
 * responsibility to comply with third-party license terms applicable to your
 * use of third-party software (including open source software) that may
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
 *
 ******************************************************************************/

#include "../../../ocpp16-manager/ocpp_process.h"
#include "../../../utilities/chargerconfigurationdatabase.h"
#include "../../../utilities/common.h"

/* Global variables for handling ChangeConfiguration process */
static OCPP_RESPONSE_FRAME *changeConfigurationSendFrame = NULL;    /* Frame to send ChangeConfiguration response */
static RX_CHANGECONFIGURATION_T rxChangeConfiguration;              /* Structure to store received ChangeConfiguration request */
static CHANGECONFIGURATION_RESPONSE_T changeConfigurationResponse; /* Structure to store ChangeConfiguration response status */

/* Array to store the string representations of ChangeConfiguration statuses */
const char *changeConfigurationStatusType[] ={
    "Accepted",
    "Rejected",
    "RebootRequired",
    "NotSupported",
};

// Function to convert a hexadecimal string to ASCII
void hex_to_ascii(char *hex_string, char *ascii_output) {
    size_t len = strlen(hex_string);
    for (size_t i = 0; i < len; i += 2) {
        // Convert each pair of hex digits to a character
        unsigned int value;
        sscanf(&hex_string[i], "%2x", &value);
        *ascii_output++ = (char)value;
    }
    *ascii_output = '\0'; // Null-terminate the output
}

void *redirect_stdin_and_read(void *arg){
	(void)arg;
	OCPPLogMessage(LOG_ERROR, LOG_SENDING,  "Program terminating after resetting password\n");
	sleep(10);

	FILE *file;
	const char *filename = "temp_input.txt";

	// Try to open the file in read mode to check if it exists
	file = fopen(filename, "r");

	if (file) {
		// File exists, close the file
		fclose(file);
		//printf("File '%s' already exists.\n", filename);
	} else {
		// File does not exist, create and write 'x' into it
		file = fopen(filename, "w");
		if (file) {
			fputc('x', file); // Write 'x' into the file
			fclose(file);
			//printf("File '%s' did not exist. Created and wrote 'x' inside.\n", filename);
		} else {
			//printf("Error: Could not create file '%s'.\n", filename);
			return NULL; // Return an error code
		}
	}
	FILE *file_stream = freopen(filename, "r", stdin);

	OCPPLogMessage(LOG_ERROR, LOG_SENDING,  "Program terminating after resetting password\n");
	if (file_stream == NULL) {
		OCPPLogMessage(LOG_ERROR, LOG_SENDING,  "Failed to terminate program\n");
	}

	return NULL;
}

/**
 * @brief Function to reset global variables for Change Configuration.
 */
void OCPPChangeConfigurationResetGlobals(void) 
{
    changeConfigurationSendFrame = NULL;
    memset(&rxChangeConfiguration, 0, sizeof(RX_CHANGECONFIGURATION_T));
    memset(&changeConfigurationResponse, 0, sizeof(CHANGECONFIGURATION_RESPONSE_T));
}

/**
 * @brief Create the Change Configuration Response Packet.
 *
 * This function creates a JSON packet for the response to a ChangeConfiguration
 * request. It adds the status of the configuration change to the JSON object.
 *
 * @return cJSON* Pointer to the created JSON object. NULL if creation fails.
 */
static cJSON *CreateChangeConfigurationResponsePacket(void)
{
    /* Create a new JSON object for the response */
    cJSON *ChangeConfig = cJSONCreateObject();
    if (ChangeConfig == NULL)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING,  "Failed to create JSON object\n");
        return NULL;
    }

    /* Add the status of the configuration change to the JSON object */
    cJSONAddItemToObject(ChangeConfig, "status", cJSONCreateString(changeConfigurationStatusType[changeConfigurationResponse.status]));
    return ChangeConfig;
}

/**
 * @brief Send the response for the Set Charger Configuration request.
 *
 * This function sends the response for the Set Charger Configuration request
 * by creating an OCPP reply frame and passing it to the SendResponseFrame
 * function. It also handles error reporting for failed send attempts.
 */
int SendChangeConfigurationResponse(void)
{
    OCPPLogMessage(LOG_INFO, LOG_SENDING, "Sending getchargerconfigresponse uuid: %s\n\r", rxChangeConfiguration.uuid);

    /* Create the response packet */
    cJSON *responsePacket = CreateChangeConfigurationResponsePacket();
    if (responsePacket == NULL)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Failed to create response packet\n");
        return SEND_RESPONSE_FRAME_FAIL;
    }

    /* Create the OCPP reply frame */
    changeConfigurationSendFrame = CreateOCPPReplyFrame(OCPP_MESSAGE_RESPONSE_CODE, rxChangeConfiguration.uuid, responsePacket);
    if (changeConfigurationSendFrame == NULL)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Failed to create OCPP reply frame\n");
        cJSONDelete(responsePacket);
        return SEND_RESPONSE_FRAME_FAIL;
    }

    /* Once OCPP packet is made, it is passed to SendFrameToCMS function, which takecare of OCPP payload to be made and then send it to server */
    if (SendResponseFrame(changeConfigurationSendFrame) != SEND_RESPONSE_FRAME_SUCCESS)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Not able to send packet, please check websocket connection\n");
        return SEND_RESPONSE_FRAME_FAIL;
    }

    /* Set the current OCPP frame transmission state */
    SetCurrentOCPPFrameTrasmittState(GET_CONFIGURATION);
    return SEND_RESPONSE_FRAME_SUCCESS;
}

/**
 * @brief Set the status of the Change Configuration response.
 *
 * This function sets the status of the Change Configuration response based
 * on the provided status value.
 *
 * @param Status The status value to be set.
 */
void SetChangeConfigurationStatus(CHANGE_CONFIGURATION_STATUS_T status)
{
    /* Set the response status based on the provided status value */
    switch (status)
    {
    case CHANGE_CONFIGURATION_ACCEPTED:
        changeConfigurationResponse.status = CHANGE_CONFIGURATION_ACCEPTED;
        break;
    case CHANGE_CONFIGURATION_REJECTED:
        changeConfigurationResponse.status = CHANGE_CONFIGURATION_REJECTED;
        break;
    case CHANGE_CONFIGURATION_REBOOT_REQUIRED:
        changeConfigurationResponse.status = CHANGE_CONFIGURATION_REBOOT_REQUIRED;
        break;
    default:
        changeConfigurationResponse.status = CHANGE_CONFIGURATION_NOT_SUPPORTED;
        break;
    }
}

CHANGE_CONFIGURATION_STATUS_T GetTxChangeConfigurationStatus()
{
    return changeConfigurationResponse.status;
}

/**
 * @brief Initialize the Change Configuration response status.
 *
 * This function initializes the Change Configuration response status to
 * "Rejected" by default.
 */
void ChangeConfigurationInit(void)
{
    changeConfigurationResponse.status = CHANGE_CONFIGURATION_REJECTED;
}

/**
 * @brief Get the Change Configuration parameters.
 *
 * This function retrieves the key and value parameters from the received
 * Change Configuration request.
 *
 * @param key Buffer to store the retrieved key.
 * @param value Buffer to store the retrieved value.
 */
void GetChangeConfigurationParms(char *key, char *value)
{
    if (key != NULL && value != NULL)
    {
        (void)SafeStringCpy(key, rxChangeConfiguration.key, sizeof(rxChangeConfiguration.key));
        (void)SafeStringCpy(value, rxChangeConfiguration.value, sizeof(rxChangeConfiguration.value));
    }
}

bool SetChangeConfigurationKey(char* key)
{

    if (key == NULL)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Configuration key is NULL\n\r");
        return false;
    }
    
    if (key[0] == '\0')
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Empty configuration key\n\r");
        return false;
    }

    if (strlen(key) >= CISTRING_50TYPE_LENGTH)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Configuration key too long: %s\n\r", key);
        return false;
    }

    (void)SafeStringCpy(rxChangeConfiguration.key, key, CISTRING_50TYPE_LENGTH);

    if (strcmp(rxChangeConfiguration.key, key) != 0)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Failed to set configuration key\n\r");
        return false;
    }

    OCPPLogMessage(LOG_DEBUG, LOG_SENDING, "Successfully set configuration key: %s\n\r", key);
    return true;
}

bool SetChangeConfigurationValue(char* value)
{

    if (value == NULL)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Configuration value is NULL\n\r");
        return false;
    }
    
    if (value[0] == '\0')
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Empty configuration value\n\r");
        return false;
    }

    if (strlen(value) >= CISTRING_500TYPE_LENGTH)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Configuration value too long\n\r");
        return false;
    }

    (void)SafeStringCpy(rxChangeConfiguration.value, value, CISTRING_500TYPE_LENGTH);

    if (strcmp(rxChangeConfiguration.value, value) != 0)
    {
        OCPPLogMessage(LOG_ERROR, LOG_SENDING, "Failed to set configuration value\n\r");
        return false;
    }

    OCPPLogMessage(LOG_DEBUG, LOG_SENDING, "Successfully set configuration value for key %s: %s\n\r", rxChangeConfiguration.key, value);
    return true;
}


/**
 * @brief Process the Change Configuration request.
 *
 * This function processes the received Change Configuration request by
 * extracting the necessary parameters, updating the charger configuration,
 * and sending the response.
 *
 * @param rx Pointer to the received OCPP frame.
 * @return int 1 if the request is successfully processed, 0 otherwise.
 */
int ProcessChangeConfigurationRequest(void *rxOcppFrame)
{
    OCPP_FRAME *rx = (OCPP_FRAME *)rxOcppFrame;
    char value[CISTRING_500TYPE_LENGTH] = {0};
    char decoded_value[CISTRING_500TYPE_LENGTH] = {0};
    if (rx == NULL || rx->action == NULL || rx->messageID == NULL || rx->jsonPacket == NULL)
    {
        OCPPLogMessage(LOG_ERROR, LOG_RECEIVED,  "Invalid Change Configuration request OCPP frame received\n");
        return OCPP_PROCESS_REQUEST_NOT_OK;
    }

    /* Check if the action is "ChangeConfiguration" */

    if (strstr(cJSONGetObjectItem(rx->jsonPacket, "key")->valuestring, "AuthorizationKey") != NULL)
    {//Write AuthKey into file passwordDB
    	FILE *file;
    	file = fopen("passwordDB", "r");  // Try to open for reading
    	if (file == NULL) {
    		// If file doesn't exist, create it
    		file = fopen("passwordDB", "w");  // Open file for writing (create if doesn't exist)
    		if (file == NULL) {
    			return OCPP_PROCESS_REQUEST_NOT_OK;  // Exit with an error if the file can't be opened
    		}
    	} else {
    		fclose(file);  // Close the file after checking existence
    		file = fopen("passwordDB", "w");  // Open file for appending
    	}
    	//hex_to_ascii(value,decoded_value);
    	memset(value,0u, sizeof(value));
    	sprintf(value, "%s", cJSONGetObjectItem(rx->jsonPacket, "value")->valuestring);
    	hex_to_ascii(value,decoded_value);
    	// Write the value into the file
    	if (fwrite(decoded_value, sizeof(char), strlen(value), file) != strlen(value)) {
    		fclose(file);
    		return OCPP_PROCESS_REQUEST_NOT_OK;
    	}

    	fclose(file);
    	(void)SafeStringCpy(rxChangeConfiguration.uuid, rx->messageID, UUID_LENGTH);
    	pthread_t thread_id;
    	pthread_create(&thread_id, NULL, redirect_stdin_and_read, NULL);
    	SetChangeConfigurationStatus(CHANGE_CONFIGURATION_ACCEPTED);
    	(void)SendChangeConfigurationResponse();
    	return OCPP_PROCESS_REQUEST_OK;
    }
    if (!strncmp(rx->action, "ChangeConfiguration", strlen(rx->action)))
    {
        OCPPLogMessage(LOG_INFO, LOG_RECEIVED, "Processing ChangeConfiguration %s\n\r", rx->messageID);
        (void)SafeStringCpy(rxChangeConfiguration.uuid, rx->messageID, UUID_LENGTH);

        /* Print the received JSON packet */
        char *jsonString = cJSONPrint(rx->jsonPacket);
        if (jsonString != NULL)
        {
            OCPPLogMessage(LOG_INFO, LOG_RECEIVED, "ChangeConfiguration: Json %s\n\r", jsonString);
            free(jsonString);
        }


        /* Extract and store the 'key' from the JSON packet */
        if (cJSONHasObjectItem(rx->jsonPacket, "key") == 1)
        {
            sprintf(rxChangeConfiguration.key, "%s", cJSONGetObjectItem(rx->jsonPacket, "key")->valuestring);
            /* Extract and store the 'value' from the JSON packet */
            if (cJSONHasObjectItem(rx->jsonPacket, "value") == 1)
            {
                char* objectValue = cJSONGetObjectItem(rx->jsonPacket, "value")->valuestring;
                if(atoi(objectValue) == -1)
                {
                    OCPPLogMessage(LOG_WARN, LOG_RECEIVED, "Invalid ChangeConfiguration value\n\r");
                    SetChangeConfigurationStatus(CHANGE_CONFIGURATION_REJECTED);
                }
                else
                {
                    char type[STANDARD_CONFIG_PARAMS_LENGTH] = {0};
                    //char value[CISTRING_500TYPE_LENGTH] = {0};
                    char readonly[STANDARD_CONFIG_PARAMS_LENGTH] = {0};
                    GetChargerConfigurationWithKey(rxChangeConfiguration.key, type, value, readonly);
                    if((strcmp(type, "CSL ") == 0))
                    {
                        char key[STANDARD_CONFIG_PARAMS_LENGTH] = {0};
                        uint16_t NoOfValues;

                        sprintf(key, "%sMaxLength", rxChangeConfiguration.key);
                        (void)GetChargerConfigurationWithKey(key, type, value, readonly);
                        NoOfValues = atoi(value);
                        if(NoOfValues == 0u)
                        {
                            /* If a key value is defined as a CSL, it MAY be accompanied with a [KeyName]MaxLength key, indicating the max
                            length of the CSL in items. If this key is not set, a safe value of 1 (one) item SHOULD be assumed */
                            NoOfValues = 1u;
                        }
                        memset(rxChangeConfiguration.value, 0u, sizeof(rxChangeConfiguration.value));
                        memset(value,0u, sizeof(value));
                        sprintf(value, "%s", cJSONGetObjectItem(rx->jsonPacket, "value")->valuestring);

                        char *token = strtok(value, ",");
                        uint16_t count = 0u;
                        while ((token != NULL) && (count < NoOfValues) )
                        {
                            strncat(rxChangeConfiguration.value, token, sizeof(rxChangeConfiguration.value) - strlen(rxChangeConfiguration.value) - 1);
                            count++;
                            token = strtok(NULL, ",");
                            if(((token != NULL) && (count < NoOfValues)) )
                            {
                                strncat(rxChangeConfiguration.value, ",", sizeof(rxChangeConfiguration.value) - strlen(rxChangeConfiguration.value) - 1);
                            }
                        }
                    }
                    else
                    {
                        sprintf(rxChangeConfiguration.value, "%s", cJSONGetObjectItem(rx->jsonPacket, "value")->valuestring);
                    }
                    /* Update the charger configuration and send the response if value is valid */
                    ChangeConfigurationUpdate(rxChangeConfiguration);
                }
            }
            else
            {
                OCPPLogMessage(LOG_WARN, LOG_RECEIVED, "ChangeConfiguration: value is not avaialble\n\r");
                SetChangeConfigurationStatus(CHANGE_CONFIGURATION_REJECTED);
            }
        }
        else
        {

            SetChangeConfigurationStatus(CHANGE_CONFIGURATION_REJECTED);
        }
        if (changeConfigurationResponse.status == CHANGE_CONFIGURATION_ACCEPTED)
        {
            OCPPProcessReportToApplication(CHANGE_CONFIGURATION, CHANGE_CONFIGURATION_ACCEPTED);
        }
        else
        {
        	(void)SendChangeConfigurationResponse();
        }
        return OCPP_PROCESS_REQUEST_OK;
    }
    return OCPP_PROCESS_REQUEST_NOT_OK;
}
