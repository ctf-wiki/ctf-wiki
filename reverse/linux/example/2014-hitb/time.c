static int t = 0x31337;

void sleep(int sec) {
	t += sec;
}

int time() {
	return t;
}
