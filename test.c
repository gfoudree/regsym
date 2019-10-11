int add_const(int c) {
	return c + 22;
}

int ab_subtraction(int a, int b) {
	return b - a;
}

int shift_add(int a) {
	return (a >> 2) + 3;
}

int unused_param_add(int a, int b, int c) {
	return c + 25;
}

int and_xor(int a) {
	return (int)((a & 0xffffffffcccc) ^ 0xddaaccbb);
}

int div_add(int a) {
	return (a / 3) + 44;
}

int mul_xor(int a, int b, int c) {
	return (a * b) ^ c;
}

int shift_mul_add(int a) {
	return (a << 2) * 3 + 4;
}

int or_shift(int a) { //Check disassembly, compiler optimizes(?) this to 0x1f because of the shift
	return (a | 0xff) >> 3;
}

int triple_add(int a, int b, int c) {
	return a + b + c;
}

int triple_add_shift(int a, int b, int c) {
	return (a + b + c) >> 2;
}

int triple_add_shift_param(int a, int b, int c, int d) {
	return (a + b + c) >> d;
}

int add_mod(int a, int mod) {
	return (a + 77) % mod;
}

int or_sub(int a, int sub) {
	return (a | 0xffffeeeeddd) - sub;
}

int main() {
	return 5;
}
