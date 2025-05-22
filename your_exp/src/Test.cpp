#include "../include/Test.h"


int main() {
    cout << "--------------- Test gmp submodule ---------------" << endl;
    mpz_class a = 0x11111_mpz;
    mpz_class b = 0x11111_mpz;
    cout << "a = ";
    show_mpz(a.get_mpz_t());
    cout << "b = ";
    show_mpz(b.get_mpz_t());
    mpz_class sum = a + b;
    cout << "a + b = ";
    show_mpz(sum.get_mpz_t());
    sum = a * b;
    cout << "a * b = ";
    show_mpz(sum.get_mpz_t());

    cout << "--------------- Test miracl_core submodule ---------------" << endl;
    BIG q;
    BIG_rcopy(q, CURVE_Order);
    cout << "Elliptic curve group order:" << endl << "q = ";
    BIG_output(q);
    cout << endl;

    ECP A;
    ECP_generator(&A);
    cout << "Generator of the elliptic curve group G1 (ECP):" << endl << "P = ";
    ECP_output(&A);

    BIG r;
    BIG_copy(r, q);
    BIG_dec(r, 122);
    ECP_mul(&A, r);
    cout << "Result of scalar multiplication a·P, where a = q - 122:" << endl << "aP = ";
    ECP_output(&A);

    return 0;
}
