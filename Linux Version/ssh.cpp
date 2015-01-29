#include <iostream>
#include <cstdlib>
#include <libssh/libssh.h>
#include<stdio.h>
#include<string.h>
#include<errno.h>

using namespace std;

#define USERNAME "vlad.traista"
#define HOSTNAME "fep.grid.pub.ro"
#define PASSWORD "ubuntu"
#define PUBKEY_FILE "/home/vlad/.ssh/id_rsa.pub"
#define PRIVKEY_FILE "/home/vlad/.ssh/id_rsa"

int verify_knownhost(ssh_session session)
{
	int state, hlen;
	unsigned char *hash = NULL;
	char *hexa;
	char buf[10];

	state = ssh_is_server_known(session);
	hlen = ssh_get_pubkey_hash(session, &hash);

	if (hlen < 0)
		return -1;

	switch (state)
	{
		case SSH_SERVER_KNOWN_OK:
			break; /* ok */

		case SSH_SERVER_KNOWN_CHANGED:
			fprintf(stderr, "Host key for server changed: it is now:\n");
			ssh_print_hexa("Public key hash", hash, hlen);
			fprintf(stderr, "For security reasons, connection will be stopped\n");
			free(hash);
			return -1;

		case SSH_SERVER_FOUND_OTHER:
			fprintf(stderr, "The host key for this server was not found but an other"
			"type of key exists.\n");
			fprintf(stderr, "An attacker might change the default server key to"
			"confuse your client into thinking the key does not exist\n");
			free(hash);
			return -1;

		case SSH_SERVER_FILE_NOT_FOUND:
			fprintf(stderr, "Could not find known host file.\n");
			fprintf(stderr, "If you accept the host key here, the file will be"
			"automatically created.\n");
			/* fallback to SSH_SERVER_NOT_KNOWN behavior */

		case SSH_SERVER_NOT_KNOWN:
			hexa = ssh_get_hexa(hash, hlen);
			fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
			fprintf(stderr, "Public key hash: %s\n", hexa);
			free(hexa);
			if (fgets(buf, sizeof(buf), stdin) == NULL)
			{
				free(hash);
				return -1;
			}
			if (strncasecmp(buf, "yes", 3) != 0)
			{
				free(hash);
				return -1;
			}
			if (ssh_write_knownhost(session) < 0)
			{
				fprintf(stderr, "Error %s\n", strerror(errno));
				free(hash);
				return -1;
			}
			break;

		case SSH_SERVER_ERROR:
			fprintf(stderr, "Error %s", ssh_get_error(session));
			free(hash);
			return -1;
	}
	free(hash);
	return 0;
}

int main(){
	ssh_session session = ssh_new();
	ssh_channel channel;
	int verbosity = SSH_LOG_PROTOCOL;
	int port = 22;
	int rc;
	int nbytes;
	char buffer[512];
	ssh_key pubkey;
	ssh_key privkey;

	if (session == NULL)
		exit(-1);

	ssh_options_set(session, SSH_OPTIONS_USER, USERNAME);
	ssh_options_set(session, SSH_OPTIONS_HOST, HOSTNAME);
	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);


	rc = ssh_connect(session);
	if (rc != SSH_OK){
		cout << "Connection failed" << endl;
		ssh_free(session);
		exit(-1);
	}

	if (verify_knownhost(session) < 0){
		cout << "Host could not be verified" << endl;
		ssh_disconnect(session);
		ssh_free(session);
		exit(-1);
	}

	rc = ssh_pki_import_pubkey_file(PUBKEY_FILE, &pubkey);
	if (rc != SSH_OK){
		cout << "Could not retrieve the public key" << endl;
		exit(-1);
	}

	rc = ssh_userauth_try_publickey(session, NULL, pubkey);
	if (rc != SSH_AUTH_SUCCESS){
		cout << "Could not pass the pubkey to the server" << endl;
		exit(-1);
	}

	rc = ssh_pki_import_privkey_file(PRIVKEY_FILE, NULL, NULL, NULL, &privkey);
	if (rc != SSH_OK){
		cout << "Could not retrieve the private key" << endl;
		exit(-1);
	}

	rc = ssh_userauth_publickey(session, NULL, privkey);
	if (rc != SSH_AUTH_SUCCESS){
		cout << "Could not authenticate to the server" << endl;
		exit(-1);
	}

	// Password authentication
	/*
	rc = ssh_userauth_password(session, NULL, PASSWORD);
	if (rc != SSH_AUTH_SUCCESS){
		fprintf(stderr, "Error authenticating with password: %s\n",
				ssh_get_error(session));
		ssh_disconnect(session);
		ssh_free(session);
		exit(-1);
	}
*/

	channel = ssh_channel_new(session);
	if (channel == NULL)
		return SSH_ERROR;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK){
		cout << "Opening session failed" << endl;
		ssh_channel_free(channel);
		exit(-1);
	}

	rc = ssh_channel_request_exec(channel, "echo \"22\" > /dev/null; echo $?");
	if (rc != SSH_OK){
		cout << "Executing command failed" << endl;
		exit(-1);
	}

	nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);

/*
	channel = ssh_channel_new(session);
	if (channel == NULL)
		return SSH_ERROR;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK){
		cout << "Opening session failed" << endl;
		ssh_channel_free(channel);
		exit(-1);
	}

	rc = ssh_channel_request_exec(channel, "ls");
	if (rc != SSH_OK){
		cout << "Executing command failed" << endl;
		exit(-1);
	}

	nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
*/
	cout << nbytes << endl;
	fwrite(buffer, 1, nbytes, stdout);

	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);

	ssh_disconnect(session);
	ssh_free(session);
	return 0;
}
