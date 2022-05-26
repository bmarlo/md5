## Usage

```C++
#include <marlo/md5.hpp>
#include <iostream>

int main(int argc, char** argv)
{
    std::string s;
    for (int i = 1; i < argc; i++) {
        s.append(argv[i]).push_back(' ');
    }

    if (!s.empty()) {
        s.pop_back();
    }
    std::cout << marlo::md5::eval(s) << '\n';
    return 0;
}

```
