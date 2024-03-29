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
