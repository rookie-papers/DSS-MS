#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

#include <iostream>
#include "Signer.h"

using namespace std;

/**
 * Sends the sanitized signature received from the signer to the verifier for verification
 * @param msg_to_send The signature received from the signer, along with some public parameters
 */
void forward_to_C(const std::string& msg_to_send);

