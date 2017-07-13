int foo(int a1, int a2, int a3)
{
 	int v4 = a1;
	int v8 = a2;
	int vC = a3;

	return v4 + v8 * vC;
}

int main()
{
 	int v4 = 1;
	v4 = foo(1, 2, 3);
	_printf("%d\n", v4);

	return 0;
}

