int main()
{
	int var_14=0;
	int var_18=123123;
	int var_10= &var_18;
	var_10 ^= var_14;
	var_14 ^= var_10;
	var_10 ^= var_14;
	printf("Please Input (int) : ");
	scanf("%d", &var_14);
	printf("\n\nYour Input (int) : %d\n\n", var_18);
	return 0;

}