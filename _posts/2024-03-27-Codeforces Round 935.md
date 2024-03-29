---
title: Codeforces Round 935
date: 2024-03-27 14-21-44
categories: [coding]
tags: [Codeforces]
image: /assets/image/image.png
math: true
---
[link contest](https://codeforces.com/contest/1945)
# A. Setting up Camp

```python
n = int(input())
for i in range(n):
    a, b, c = map(int, input().split())
    res = a + b//3
    du = b % 3
    conlai = (b % 3+c)

    if conlai // 3 == 0 and du != 0:
        print("-1")
    else:
        res += conlai//3
        conlai %= 3
        if conlai:
            res += 1
        print(res)
```

# B. Fireworks

```python
import builtins
n = int(input())
for i in range(n):
    a, b, m = map(int, input().split())
    print(m//a + m//b + 2)

```
# D - Seraphim the Owl

```python
#include <stdio.h>
#include <stdlib.h>
long long a[300000];
long long b[300000];
long long min(long long a, long long b)
{
    if (a > b)
        return b;
    else
        return a;
}

int main()
{
    int cnt;
    scanf("%d", &cnt);
    while (cnt--)
    {
        long long n, m;
        scanf("%lld%lld", &n, &m);
        for (int i = 1; i <= n; i++)
            scanf("%lld", &a[i]);
        for (int i = 1; i <= n; i++)
            scanf("%lld", &b[i]);
        long long sum = 0;
        for (int i = m + 1; i <= n; i++)
        {
            sum += min(a[i], b[i]);
        }
        long long tmp = 1e14, ans = 0;
        for (int i = m; i >= 1; i--)
        {
            tmp = min(tmp, ans + a[i]);
            ans += b[i];
        }
        printf("%lld\n", sum+tmp);
    }
}
```