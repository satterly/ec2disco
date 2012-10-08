#include <curl/curl.h>
#include <openssl/hmac.h>
#include <uuid/uuid.h>
#include <apr-1/apr.h>
#include <apr-1/apr_strings.h>
#include <apr-1/apr_time.h>
#include <apr-1/apr_base64.h>
#include <apr-1/apr_xml.h>

struct MemoryStruct {
    char *memory;
    size_t size;
};


static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *) userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL) {
	/* out of memory! */
	printf("not enough memory (realloc returned NULL)\n");
	exit(EXIT_FAILURE);
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int main(int argc, char *argv[])
{

    CURLcode res;
    CURL *curl_handle;

    struct MemoryStruct chunk;

    chunk.memory = malloc(1);	/* will be grown as needed by the realloc above */
    chunk.size = 0;		/* no data at this point */

    const char *ec2_api_endpoint = "https://ec2.amazonaws.com/";

    unsigned char *aws_access_key_id = "AKIAIM3EQ4SCWGT6UZBA";
    unsigned char *aws_secret_access_key = "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";

    apr_status_t rv;
    apr_pool_t *mp;		/* main pool */

    apr_initialize();
    apr_pool_create(&mp, NULL);

    char timestamp[30];
    apr_size_t len;

    {
	apr_time_exp_t t;
	apr_time_exp_lt(&t, apr_time_now());
	apr_strftime(timestamp, &len, sizeof(timestamp), "%Y-%m-%dT%H%%3A%M%%3A%SZ", &t);
    }

    /* FIXME Need to allow query for tags and group as well */
    char *signature_string;
    signature_string =
	apr_pstrcat(mp, "GET\n", "ec2.amazonaws.com\n", "/\n",
		    "AWSAccessKeyId=", aws_access_key_id,
		    "&Action=DescribeInstances",
		    "&SignatureMethod=HmacSHA256", "&SignatureVersion=2",
		    "&Timestamp=", timestamp, "&Version=2012-08-15", NULL);
    // printf("signature string = %s\n", signature_string);

    char hash[EVP_MAX_MD_SIZE];
    int hlen;
    HMAC(EVP_sha256(), aws_secret_access_key,
	 strlen(aws_secret_access_key), (unsigned char *) signature_string, strlen(signature_string), hash, &hlen);

    /* base64 encode the signature string */
    int elen;
    char *encbuf;
    elen = apr_base64_encode_len(hlen);
    encbuf = apr_palloc(mp, elen);
    apr_base64_encode(encbuf, hash, hlen);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl_handle = curl_easy_init();
    if (curl_handle) {
	char *urlencoded_hash = curl_easy_escape(curl_handle, encbuf, 0);

	char *request;
	request =
	    apr_pstrcat(mp, ec2_api_endpoint, "?AWSAccessKeyId=",
			aws_access_key_id,
			"&Action=DescribeInstances&Signature=",
			urlencoded_hash,
			"&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=",
			timestamp, "&Version=2012-08-15", NULL);
	printf("HTTP request: %s\n", request);

	curl_easy_setopt(curl_handle, CURLOPT_URL, request);

	/* send all data to this function  */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

	/* we pass our 'chunk' struct to the callback function */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &chunk);

	res = curl_easy_perform(curl_handle);

	/* Check for errors */
	if (res != CURLE_OK)
	    fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

	/* always cleanup */
	curl_easy_cleanup(curl_handle);
    }

    printf("%lu bytes retrieved\n", (long) chunk.size);

    char *response = chunk.memory;

    if (chunk.memory)
	free(chunk.memory);

    curl_global_cleanup();

    printf("Response %s\n", response);

    apr_xml_doc *doc;
    apr_xml_elem *node;
    apr_xml_parser *parser = apr_xml_parser_create(mp);

    /* parse the XML response */
    if (apr_xml_parser_feed(parser, response, strlen(response)) != APR_SUCCESS) {
        printf("error");
    }
    /* retrieve a DOM object */
    if (apr_xml_parser_done(parser, &doc) != APR_SUCCESS) {
        printf("error");
    }

    apr_xml_elem *root;
    root = doc->root;
    const apr_xml_elem *elem;
    
    for (elem = root->first_child; elem; elem = elem->next) {
        printf("name = %s\n", elem->name);
        const apr_xml_elem *elem2;
        const apr_xml_attr *attr;
        for (elem2 = elem->first_child; elem2; elem2 = elem2->next) {
            printf("  name = %s\n", elem2->name);
            for (attr = elem2->attr; attr; attr = attr->next) {
                printf("  attr: name = %s, text = %s\n", attr->name, attr->value);
            }
            const apr_xml_elem *elem3;
            for (elem3 = elem2->first_child; elem3; elem3 = elem3->next) {
                printf("    name = %s\n", elem3->name);
                const apr_xml_elem *elem4;
                for (elem4 = elem3->first_child; elem4; elem4 = elem4->next) {
                    printf("      name = %s\n", elem4->name);
                    const apr_xml_elem *elem5;
                    for (elem5 = elem4->first_child; elem5; elem5 = elem5->next) {
                        printf("      name = %s\n", elem5->name);
                        if (apr_strnatcmp(elem5->name, "dnsName") == 0)
                            printf("      dnsName = %s\n", elem5->first_cdata.first->text);
                        if (apr_strnatcmp(elem5->name, "groupSet") == 0) {
                            const apr_xml_elem *elem6;
                            for (elem6 = elem5->first_child; elem6; elem6 = elem6->next) {
                                printf("        name = %s\n", elem6->name);
                                const apr_xml_elem *elem7;
                                for (elem7 = elem6->first_child; elem7; elem7 = elem7->next) {
                                    if (apr_strnatcmp(elem7->name, "groupId") == 0)
                                        printf("          groupId = %s\n", elem7->first_cdata.first->text);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    apr_terminate();
    return 0;
}