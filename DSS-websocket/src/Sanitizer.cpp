#include "../include/Sanitizer.h"

typedef websocketpp::server<websocketpp::config::asio> server;
typedef server::message_ptr message_ptr;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

typedef websocketpp::client<websocketpp::config::asio_client> client;
typedef websocketpp::config::asio_client::message_type::ptr message_ptr;


void on_message(server* s, websocketpp::connection_hdl hdl, message_ptr msg) {
    std::string received = msg->get_payload();
    // 1. Deserialize the received content
    TransmissionPackage pkg = str_to_Package(received);
    showPackage(pkg);
    // 2. Perform the sanitizing operation
    gmp_randstate_t state;
    initState(state);
    Sigma sigma_p = Sanitizing(pkg.pp, pkg.sigma, pkg.sk_i, pkg.PK_san, state);
    // 3. Construct a new package (to be sent to C, no longer includes sk_i)
    TransmissionPackage pkg_to_C;
    pkg_to_C.pp = pkg.pp;
    pkg_to_C.sigma = pkg.sigma;
    pkg_to_C.PK_san = pkg.PK_san;
    pkg_to_C.PK_sig = pkg.PK_sig;
    // 4. Connect to Verifier and forward the data as a client
    std::string output = Package_to_str(pkg_to_C);
    forward_to_C(output);  // Custom function, see below
}

void forward_to_C(const std::string &msg_to_send) {
    typedef websocketpp::client<websocketpp::config::asio_client> client;
    client c;
    std::string uri = "ws://localhost:9003"; // Verifier's listening address
    // === Network configuration ===
    c.set_access_channels(websocketpp::log::alevel::all);
    c.clear_access_channels(websocketpp::log::alevel::frame_payload);
    c.init_asio();
    // Send msg_to_send directly in the open handler, no external variable dependency
    c.set_open_handler([&c, msg_to_send](websocketpp::connection_hdl hdl) {
        std::cout << "[Forward] Connected to C. Sending...\n";
        websocketpp::lib::error_code ec;
        c.send(hdl, msg_to_send, websocketpp::frame::opcode::text, ec);
        if (ec) {
            std::cerr << "[Forward] Send failed: " << ec.message() << std::endl;
        }
    });

    websocketpp::lib::error_code ec;
    client::connection_ptr con = c.get_connection(uri, ec);
    if (ec) {
        std::cout << "Connection failed: " << ec.message() << std::endl;
        return;
    }

    c.connect(con);
    std::thread th([&c]() { c.run(); });
    if (th.joinable()) th.join();
    c.run();
}



int main() {
    server echo_server;

    try {
        echo_server.set_access_channels(websocketpp::log::alevel::all);
        echo_server.clear_access_channels(websocketpp::log::alevel::frame_payload);
        echo_server.init_asio();
        echo_server.set_message_handler(bind(&on_message, &echo_server, _1, _2));
        echo_server.listen(9002);
        echo_server.start_accept();
        std::cout << "Sanitizer is listening on port 9002..." << std::endl;
        echo_server.run();
    } catch (const std::exception &e) {
        std::cout << "Server exception: " << e.what() << std::endl;
    }
}
