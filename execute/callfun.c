#include <stdio.h>
#define UDEC unsigned long long

void fun1() {
	printf("fun1 ");
	return;
}

void fun2(){
	int a = 0xA;
	int b = 0xF;
	int c = a + b;
	printf("fun2 ");
	return;
}

int fun3(){
	printf("fun3 ");
	return 0;
}

int fun4(int a){
	printf("fun4 ");
	return -a;
}

int fun5(int a, int b){
	printf("fun5 ");
	return a + b;
}

int main(){
	int rt;
	fun1();
	fun2();
	rt = fun3();
	rt = fun4(0x100);
	rt = fun5(10, 0xABCDF123);

	printf("OFFSETS 0x%llX, 0x%llX, 0x%llX, 0x%llX, 0x%llX, 0x%llX\n", (UDEC)fun1, (UDEC)fun2, (UDEC)fun3, (UDEC)fun4, (UDEC)fun5, (UDEC)main);
	return 0;
}