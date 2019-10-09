int _baz(int c) {
	return c + 22;
}

int _bar(int a, int b) {
	return b - a;
}

int shift_add(int a) {
	return (a >> 2) + 3;
}
int main() {
	return _baz(4) + _bar(3, 4);
}
