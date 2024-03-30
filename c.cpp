#include <iostream>
#include <math.h>
#include <algorithm>
using namespace std;

int main()
{
    int t;
    cin >> t;
    while (t--)
    {
        int n, cnt = 1;
        cin >> n;
        int a[n + 5];
        for (int i = 1; i <= n; i++)
            cin >> a[i];
        sort(a + 1, a + 1 + n);
        int mid_idx = ceil(1.00 * n / 2);
        int mid_val = a[mid_idx];
        for (int i = mid_idx+1; i <= n; i++)
        {
            if (a[i] == mid_val)
            {

                cnt++;
            }
            else break;
        }
        cout << cnt << "\n";
    }
}