                                                      RSA Algorithm in Cryptography

Code:
#include <bits/stdc++.h>
using namespace std;

int gcd(int a, int h)
{
	int temp;
	while (1) {
		temp = a % h;
		if (temp == 0)
			return h;
		a = h;
		h = temp;
	}
}

int main()
{
	double p = 3;
	double q = 7;

	double n = p * q;


	double e = 2;
	double phi = (p - 1) * (q - 1);
	while (e < phi) {
		// e must be co-prime to phi and
		// smaller than phi.
		if (gcd(e, phi) == 1)
			break;
		else
			e++;
	}

	int k = 2; // A constant value
	double d = (1 + (k * phi)) / e;

	double msg = 12;

	printf("Message data = %lf", msg);

	double c = pow(msg, e);
	c = fmod(c, n);
	printf("\nEncrypted data = %lf", c);

	double m = pow(c, d);
	m = fmod(m, n);
	printf("\nOriginal Message Sent = %lf", m);

	return 0;
}


Output:

Message data = 12.000000
Encrypted data = 3.000000
Original Message Sent = 12.000000
