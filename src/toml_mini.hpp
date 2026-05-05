// toml_mini.hpp — minimal TOML parser for dirblock
//
// Replaces toml11 v4 by Toru Niina (https://github.com/ToruNiina/toml11)
// which is licensed under the MIT License:
//
// Copyright (c) 2017-now Toru Niina
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Supported subset:
//   [section]                        — table headers (no dotted keys)
//   key = true / key = false         — bare key, bool value
//   key = "string"                   — bare key, string value
//   "quoted key" = "string"          — quoted key, string value
//   "quoted key" = ["a", "b", ...]   — quoted key, string array (multi-line OK)
//   # comments                       — full-line and inline (after value)
//
// NOT supported: nested tables, dotted keys, inline tables, integers, floats,
// dates/times, literal strings (''), multi-line strings ("""), unicode escapes,
// array-of-tables ([[x]]).

#pragma once

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace toml_mini {

struct Value {
    bool is_bool = false;
    bool bool_val = false;
    std::vector<std::string> string_array;
};

using Table = std::unordered_map<std::string, Value>;
using Document = std::unordered_map<std::string, Table>;

namespace detail {

inline std::string parse_error(const std::string& file, int line, const std::string& msg) {
    return file + ":" + std::to_string(line) + ": " + msg;
}

inline std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Strip inline comment (not inside a quoted string)
inline std::string strip_comment(const std::string& s) {
    bool in_quote = false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '"' && (i == 0 || s[i-1] != '\\')) in_quote = !in_quote;
        if (s[i] == '#' && !in_quote) return s.substr(0, i);
    }
    return s;
}

// Parse a quoted string starting at pos (pos points to opening "). Advances pos past closing ".
inline std::string parse_quoted(const std::string& s, size_t& pos,
                                const std::string& file, int line) {
    if (pos >= s.size() || s[pos] != '"')
        throw std::runtime_error(parse_error(file, line, "expected '\"'"));
    ++pos; // skip opening "
    std::string result;
    while (pos < s.size() && s[pos] != '"') {
        if (s[pos] == '\\' && pos + 1 < s.size()) {
            ++pos;
            switch (s[pos]) {
                case '"':  result += '"'; break;
                case '\\': result += '\\'; break;
                case 'n':  result += '\n'; break;
                case 't':  result += '\t'; break;
                default:   result += '\\'; result += s[pos]; break;
            }
        } else {
            result += s[pos];
        }
        ++pos;
    }
    if (pos >= s.size())
        throw std::runtime_error(parse_error(file, line, "unterminated string"));
    ++pos; // skip closing "
    return result;
}

} // namespace detail

inline Document parse(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open())
        throw std::runtime_error("cannot open config: " + path);

    Document doc;
    std::string current_section;
    std::string line_buf;
    int lineno = 0;

    // State for multi-line arrays
    bool in_array = false;
    std::string array_key;
    std::string array_section;
    std::vector<std::string> array_vals;

    while (std::getline(in, line_buf)) {
        ++lineno;
        std::string line = detail::trim(line_buf);

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            if (in_array) continue; // blank/comment lines inside array are OK
            continue;
        }

        // If we're inside a multi-line array, collect values
        if (in_array) {
            std::string stripped = detail::trim(detail::strip_comment(line));
            // Check for closing bracket
            // Parse comma-separated quoted strings, possibly ending with ]
            size_t pos = 0;
            while (pos < stripped.size()) {
                char c = stripped[pos];
                if (c == ' ' || c == '\t' || c == ',') { ++pos; continue; }
                if (c == ']') {
                    in_array = false;
                    Value v;
                    v.string_array = std::move(array_vals);
                    doc[array_section][array_key] = std::move(v);
                    array_vals.clear();
                    break;
                }
                if (c == '"') {
                    array_vals.push_back(detail::parse_quoted(stripped, pos, path, lineno));
                } else {
                    throw std::runtime_error(detail::parse_error(path, lineno,
                        "expected '\"' or ']' in array"));
                }
            }
            continue;
        }

        // Section header: [name]
        if (line[0] == '[') {
            if (line.back() != ']')
                throw std::runtime_error(detail::parse_error(path, lineno,
                    "malformed section header"));
            current_section = detail::trim(line.substr(1, line.size() - 2));
            if (current_section.empty())
                throw std::runtime_error(detail::parse_error(path, lineno,
                    "empty section name"));
            continue;
        }

        if (current_section.empty())
            throw std::runtime_error(detail::parse_error(path, lineno,
                "key-value pair outside of section"));

        // Key = Value
        // Key is either bare (alphanumeric + _ + -) or quoted
        std::string key;
        size_t pos = 0;
        if (line[0] == '"') {
            key = detail::parse_quoted(line, pos, path, lineno);
        } else {
            size_t eq = line.find('=');
            if (eq == std::string::npos)
                throw std::runtime_error(detail::parse_error(path, lineno,
                    "expected '='"));
            key = detail::trim(line.substr(0, eq));
            pos = eq;
        }

        // Skip whitespace and '='
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) ++pos;
        if (pos >= line.size() || line[pos] != '=')
            throw std::runtime_error(detail::parse_error(path, lineno, "expected '='"));
        ++pos;
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) ++pos;

        if (pos >= line.size())
            throw std::runtime_error(detail::parse_error(path, lineno, "expected value after '='"));

        // Determine value type
        std::string rest = detail::trim(detail::strip_comment(line.substr(pos)));

        if (rest == "true" || rest == "false") {
            Value v;
            v.is_bool = true;
            v.bool_val = (rest == "true");
            doc[current_section][key] = std::move(v);
        } else if (rest[0] == '"') {
            // Single string value
            size_t spos = 0;
            std::string s = detail::parse_quoted(rest, spos, path, lineno);
            Value v;
            v.string_array.push_back(std::move(s));
            doc[current_section][key] = std::move(v);
        } else if (rest[0] == '[') {
            // Array — could be single-line or multi-line
            std::string arr_content = rest.substr(1);
            std::vector<std::string> vals;
            size_t apos = 0;
            std::string stripped = detail::trim(arr_content);
            bool closed = false;

            while (apos < stripped.size()) {
                char c = stripped[apos];
                if (c == ' ' || c == '\t' || c == ',') { ++apos; continue; }
                if (c == ']') { closed = true; break; }
                if (c == '"') {
                    vals.push_back(detail::parse_quoted(stripped, apos, path, lineno));
                } else {
                    throw std::runtime_error(detail::parse_error(path, lineno,
                        "expected '\"' or ']' in array"));
                }
            }

            if (closed) {
                Value v;
                v.string_array = std::move(vals);
                doc[current_section][key] = std::move(v);
            } else {
                // Multi-line array
                in_array = true;
                array_key = key;
                array_section = current_section;
                array_vals = std::move(vals);
            }
        } else {
            throw std::runtime_error(detail::parse_error(path, lineno,
                "unsupported value type (expected bool, string, or array)"));
        }
    }

    if (in_array)
        throw std::runtime_error(detail::parse_error(path, lineno,
            "unterminated array for key '" + array_key + "'"));

    return doc;
}

} // namespace toml_mini
