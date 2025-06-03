#include "../include/Verifier.h"

using namespace std;
typedef websocketpp::server<websocketpp::config::asio> server;
typedef server::message_ptr message_ptr;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

void on_message(server* s, websocketpp::connection_hdl hdl, message_ptr msg) {
    std::string payload = msg->get_payload();
    std::cout << "[C] Received message from B\n" << endl << payload;
    TransmissionPackage pkg = str_to_Package(payload);
    showPackage(pkg);
    // verify signature
    int res = Verify(pkg.pp, pkg.sigma, pkg.PK_san, pkg.PK_sig);
    cout << "Verify result : " << res << endl;
}

int main() {
    server C_server;

    try {
        C_server.set_access_channels(websocketpp::log::alevel::all);
        C_server.clear_access_channels(websocketpp::log::alevel::frame_payload);
        C_server.init_asio();
        C_server.set_message_handler(bind(&on_message, &C_server, _1, _2));
        C_server.listen(9003);
        C_server.start_accept();
        std::cout << "Verifier is listening on port 9003..." << std::endl;
        C_server.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception in C: " << e.what() << std::endl;
    }

    return 0;
}
