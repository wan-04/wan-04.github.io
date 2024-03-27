import builtins
n = int(input())
for i in range(n):
    a, b, m = map(int, input().split())
    print(m//a + m//b + 2)
    