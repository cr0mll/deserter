#include <string>
#include <vector>

std::vector<std::string> SplitString(const std::string& s, char delimiter)
{
    std::vector<std::string> v;

    std::size_t pos = s.find_first_of(delimiter, 0);
    for (std::size_t beg = 0; pos != std::string::npos; beg = pos) {
        v.emplace_back(s.substr(beg, pos));
        pos = s.find_first_of(delimiter, pos);
    }

    return v;
}