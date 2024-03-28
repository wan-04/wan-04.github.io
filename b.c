#include <stdio.h>
#include <stdlib.h>

int min(int a, int b)
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
        int m, n;
        scanf("%d%d", &n, &m);
        long long a[2][n + 5];
        for (int i = 1; i <= n; i++)
            scanf("%d", &a[0][i]);
        for (int i = 1; i <= n; i++)
            scanf("%d", &a[1][i]);
        long long res = 0;
        long long ans = 1e18;
        for (int i = 1; i <= n; i++)
        {
            if (a[0][i] <= a[1][i])
            {
                res += a[0][i];
                if (i <= m)
                    ans = min(ans, res);
            }
            else
            {
                if (i <= m)
                    ans = min(ans, res + a[0][i]);
                res += a[1][i];
            }
        }
        printf("%lld\n", ans);
    }
}
