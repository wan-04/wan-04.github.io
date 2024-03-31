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