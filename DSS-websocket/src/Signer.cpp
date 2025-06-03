#include "../include/Signer.h"

typedef websocketpp::client <websocketpp::config::asio_client> client;
typedef websocketpp::config::asio_client::message_type::ptr message_ptr;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

std::string serialized_data;  // 全局变量，在连接建立后发送


void on_open(client *c, websocketpp::connection_hdl hdl) {
    websocketpp::lib::error_code ec;
    c->send(hdl, serialized_data, websocketpp::frame::opcode::text, ec);
    if (ec) {
        std::cerr << "[Send Error] " << ec.message() << std::endl;
    } else {
        std::cout << "[Client] Data sent successfully." << std::endl;
    }
}

void on_message(client *c, websocketpp::connection_hdl hdl, message_ptr msg) {
    std::string payload = msg->get_payload();
    std::cout << "[Client] Received message: " << payload << std::endl;
    // 可选：反序列化 payload 做进一步处理
}

int main() {
    client c;
    std::string uri = "ws://localhost:9002";

    try {
        // === 数据准备 ===
        int k = 5, bits = 256;
        Params pp = Setup();

        KeyPair keyPair_san;
        std::vector<mpz_class> sk = KeyGen(pp, keyPair_san, k, bits);

        KeyPair keyPair_sign;
        keyPair_sign.sk = initAndGetMpz();
        ECP_copy(&keyPair_sign.PK, &pp.P);
        ECP_mul(keyPair_sign.PK, keyPair_sign.sk);

        mpz_class t;
        Sigma sigma = Sign(pp, keyPair_sign.sk, keyPair_san.PK, t);

        TransmissionPackage pkg;
        pkg.pp = pp;
        pkg.PK_san = keyPair_san.PK;
        pkg.sigma = sigma;
        pkg.sk_i = sk[1];
        pkg.PK_sig = keyPair_sign.PK;
        showPackage(pkg);

        serialized_data = Package_to_str(pkg);

        // === 网络设置 ===
        c.set_access_channels(websocketpp::log::alevel::all);
        c.clear_access_channels(websocketpp::log::alevel::frame_payload);
        c.init_asio();

        c.set_message_handler(bind(&on_message, &c, _1, _2));
        c.set_open_handler(bind(&on_open, &c, _1));

        websocketpp::lib::error_code ec;
        client::connection_ptr con = c.get_connection(uri, ec);
        if (ec) {
            std::cerr << "[Client] Connection failed: " << ec.message() << std::endl;
            return -1;
        }

        c.connect(con);

        std::thread th([&c]() { c.run(); });
        if (th.joinable()) th.join();

    } catch (const std::exception &e) {
        std::cerr << "[Client Exception] " << e.what() << std::endl;
    }

    return 0;
}
