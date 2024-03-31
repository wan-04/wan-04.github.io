---
title: Codeforces Round 936 (Div. 2) & Codeforces Round 937 (Div. 4)
date: 2024-03-30 03-27-39
categories: [coding]
tags: [Codeforces]
math: true
---

## Codeforces Round 936 (Div. 2)

[link contest](https://codeforces.com/contest/1946)

### A - Median of an Array

```cpp
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
```

---

## Codeforces Round 937 (Div. 4)

[contest](https://codeforces.com/contest/1950)

### A - Stair, Peak, or Neither?

```python
import builtins
n = int(input())
for i in range(n):
    a, b, c = map(int, input().split())
    if a < b and b < c:
        print("STAIR")
    elif a < b and b > c:
        print("PEAK")
    else:
        print("NONE")
```

### B. Upscaling

```cpp
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
        int n;
        cin >> n;
        for (int i = 0; i < 2 * n; i++)
        {
            for (int j = 0; j < 2 * n; j++)
            {
                if ((i % 4 < 2 && j % 4 < 2) || (i % 4 > 1 && j % 4 > 1))
                    cout << '#';
                else
                    cout << '.';
            }
            cout << endl;
        }
    }
}
```

### C. Clock Conversion

```cpp
#include <iostream>
#include <math.h>
#include <algorithm>
#include <string.h>
#include <cstdlib>
#include <iomanip>
using namespace std;

int main()
{
    int t;
    cin >> t;
    while (t--)
    {
        char str[10];
        cin >> str;
        char *p = strtok(str, ":");
        int h = atoi(p);
        // cout << h;
        p = strtok(NULL, " ");
        int m = atoi(p);
        float a = h / 12.0;
        int b = h % 12;
        if (b == 0)
            cout << "12";
        else
            cout << setw(2) << setfill('0') << b;
        cout << ":" << setw(2) << setfill('0') << m;

        if (a < 1)
            cout << " AM\n";
        else
            cout << " PM\n";
    }
}
```

### D. Product of Binary Decimals

```cpp
#include <iostream>
#include <math.h>
#include <algorithm>
#include <string.h>
#include <cstdlib>
#include <iomanip>
using namespace std;
int a[16]={10,11,101,111,1001,1011,1101,1111,11111,10111,11011,11101,10011,10001,11001,10101};
int main()
{
    int t;
    cin >> t;
    while (t--)
    {
        int n;
        cin >> n;
        bool check = true;
        int cnt = 0;
        for (int i = 15; i >= 0; i--)
        {
            while (n % a[i] == 0)
            {
                n /= a[i];
            }
        }
        if (n == true)
            cout << "YES" << endl;
        else
            cout << "NO" << endl;
    }
}
```