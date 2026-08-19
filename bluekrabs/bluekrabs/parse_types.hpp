// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#ifndef  WIN32_LEAN_AND_MEAN
#define  WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sddl.h>

#include <vector>
#include <type_traits>

#include "compiler_check.hpp"

namespace krabs {

    /**
     * <summary>
     *   Provided entirely for code clarity purposes.
     *   Indicates that the number is intended to be used as an ID
     * </summary>
     * <remarks>
     *   This should be turned into an _id user defined literal when our
     *   compiler decides to catch up to the times.
     * </remarks>
     * <example>
     *     id(1000);
     * </example>
     */
     template <typename T>
     T id(T n)
     {
        return n;
     }

    /**
     * <summary>
     *   Provided entirely for code clarity purposes.
     *   Indicates that the number is intended to be used as a version
     * </summary>
     * <remarks>
     *   This should be turned into a _vers user defined literal when our
     *   compiler decides to catch up to the times.
     * </remarks>
     * <example>
     *     id(1000);
     * </example>
     */
     template <typename T>
     T version(T n)
     {
        return n;
     }

    /**
     * <summary>
     *   Provided entirely for code clarity purposes.
     *   Indicates that the number is intended to be used as an opcode
     * </summary>
     * <remarks>
     *   This should be turned into a _opcode user defined literal when our
     *   compiler decides to catch up to the times.
     * </remarks>
     * <example>
     *     opcode(1000);
     * </example>
     */
     template <typename T>
     T opcode(T n)
     {
        return n;
     }


    /**
     * <summary>
     * Used to discriminate between hex ints and regular ints in ETW events.
     * </summary>
     * <remarks>
     * Q: Why in the world? I can't even.
     * A: ETW differentiates between hexints and regular ints. When
     *    record_builder validates that the input type matches the type
     *    specified in the schema, getting this wrong will cause an
     *    exception. A quick little type wrapper like this lets us
     *    discriminate based on the type and everything turns out better.
     * </remarks>
     */
    struct hexint32 {
        hexint32(int v)
        : value(v)
        {}

        int value;
    };

    struct hexint64 {
        hexint64(long long v)
        : value(v)
        {}

        long long value;
    };

    /**
     * <summary>
     * Used to support parsing and creation of binary ETW fields.
     * </summary>
     */
    struct binary {
    public:
        binary() : bytes_() { }

        binary(const BYTE* start, size_t n)
        : bytes_(start, start + n)
        { }

        const std::vector<BYTE>& bytes() const
        {
            return bytes_;
        }

    private:
        std::vector<BYTE> bytes_;
    };

    template<typename T>
    binary make_binary(const T& value, size_t n)
    {
        const auto start = (BYTE*)&value;
        return binary(start, n);
    }

    /**
     * <summary>
     * Used to handle parsing of IPv4 and IPv6 fields in an ETW record.
     * This is used in the parser class in a template specialization.
     * </summary>
     */
    struct ip_address {
        union {
            DWORD v4;
            BYTE v6[16];
        };
        bool is_ipv6;

        static ip_address from_ipv6(const BYTE* bytes)
        {
            ip_address addr;
            addr.is_ipv6 = true;
            memcpy_s(addr.v6, 16, bytes, 16);
            return addr;
        }

        static ip_address from_ipv4(DWORD val)
        {
            ip_address addr;
            addr.is_ipv6 = false;
            addr.v4 = val;
            return addr;
        }

        ip_address() {}
     };

    /**
    * <summary>
    * Used to handle parsing of socket addresses in
    * network order. This union is a convenient wrapper
    * around the type IPv4 and IPv6 types provided by
    * the Winsock (v2) APIs.
    * </summary>
    */
    struct socket_address {
        union {
            struct sockaddr sa;
            struct sockaddr_in sa_in;
            struct sockaddr_in6 sa_in6;
            struct sockaddr_storage sa_stor;
        };
        size_t size;

        static socket_address from_bytes(const BYTE* bytes, size_t size_in_bytes)
        {
            socket_address sa;
            memcpy_s(&(sa.sa_stor), sizeof sa.sa_stor, bytes, size_in_bytes);
            sa.size = size_in_bytes;
            return sa;
        }
    };

    /**
     * <summary>
     * Holds position-independent information about a property extracted from
     * the etw schema. All fields are relative to the record's UserData (or an
     * equivalent flat copy), so instances can be cached across events and
     * reused against any buffer holding the same wire bytes.
     * </summary>
     * <remarks>
     * Invariant: offset_ is valid iff length_ is valid. A property whose
     * offset depends on a preceding variable-length property has
     * offset_ == npos even if its own length is schema-fixed.
     * </remarks>
     */
    struct property_info {
        static constexpr ULONG npos = ULONG(-1);

        ULONG offset_;          // bytes from UserData start; npos if unknown (per-event)
        ULONG length_;          // property length in bytes; npos if unknown (per-event)
        ULONG property_index_;  // index into TRACE_EVENT_INFO::EventPropertyInfoArray

        property_info(ULONG offset, ULONG length, ULONG index)
            : offset_(offset)
            , length_(length)
            , property_index_(index)
        { }

        property_info()
            : offset_(npos)
            , length_(npos)
            , property_index_(npos)
        { }

        inline bool found() const
        {
            return property_index_ != npos;
        }

        inline bool has_offset() const { return offset_ != npos; }
        inline bool has_length() const { return length_ != npos; }

        // Reconstruct an absolute pointer to the property bytes against a raw
        // buffer holding the record's UserData (or an arena-copied equivalent).
        inline const BYTE* pointer_in(const BYTE* raw) const
        {
            return raw + offset_;
        }

        // Reconstruct the schema entry for this property. `schema` is the
        // TRACE_EVENT_INFO pointer for the record's descriptor (available via
        // schema_locator).
        inline const EVENT_PROPERTY_INFO& info_in(const TRACE_EVENT_INFO* schema) const
        {
            return schema->EventPropertyInfoArray[property_index_];
        }
    };

    static_assert(sizeof(property_info) == 12,
                  "property_info must stay 12 bytes for cache density");

    /**
     * <summary>
     * Per-descriptor property layout. One instance per descriptor; owned by
     * schema_locator, filled lazily by parser during walks. Accessed from
     * user code via class schema's layout() accessor.
     * </summary>
     * <remarks>
     * Contract: entries[i].offset_ / .length_ are npos until resolved.
     * Once i &lt; fixed_count, entries[i] holds cached offset+length good
     * for every future event of this descriptor. Entries past fixed_count
     * may still cache length_ (schema-fixed length) even if offset_ is
     * per-event.
     * </remarks>
     */
    struct property_layout {
        std::vector<property_info> entries;
        ULONG                      fixed_count;
        ULONG                      prefix_byte_end;

        property_layout()
            : fixed_count(0)
            , prefix_byte_end(0)
        { }
    };

    /**
    * <summary>
    * Used to handle parsing of SIDs from either a
    * SID or WBEMSID property
    * </summary>
    */
    struct sid {
        // SIDs are variable-length
        // So the 'best' way to store them is to convert to a string
        // The other-end can either print the string or call ConvertStringSidToSidA
        // to get the SID back
        std::string sid_string;

        static sid from_bytes(const BYTE* bytes, size_t size_in_bytes)
        {
            sid ws;
            LPSTR temp_sid_string;
            UNREFERENCED_PARAMETER(size_in_bytes);

            if (!ConvertSidToStringSidA((PSID)bytes, &temp_sid_string)) {
                throw std::runtime_error(
                    "Failed to get a SID from a property");
            }
            ws.sid_string = temp_sid_string;
            LocalFree(temp_sid_string);
            return ws;
        }

    private:
    };

    /**
    * <summary>
    * Used to handle parsing of Pointer Address types.
    * </summary>
    */
    struct pointer {
        /**
        * We store the pointer as an uint64_t, as it is highly unlikley
        * to be pointing to somewhere accessible to our process
        */
        uint64_t address;

        static pointer from_bytes(const BYTE* bytes, size_t size_in_bytes)
        {
            pointer pt;

            // If 32-Bit, first parse as a uint32
            // Then we can 'cast' that to our uint64_t
            if (size_in_bytes == sizeof(uint32_t)) {
                pt.address = *reinterpret_cast<const uint32_t*>(bytes);
            }
            else if (size_in_bytes == sizeof(uint64_t)) {
                pt.address = *reinterpret_cast<const uint64_t*>(bytes);
            }
            else {
                throw std::runtime_error(
                    "Failed to get a POINTER from a property");
            }

            return pt;
        }

    private:
    };


    /**
     * <summary>
     * Used to handle parsing of CountedStrings in an ETW Record.
     * This is used in the parser class in a template specialization.
     * </summary>
     */
#pragma pack(push,1)
    struct counted_string {
        using value_type = wchar_t;
        using reference = value_type&;
        using pointer = value_type*;
        using const_reference = const value_type&;
        using const_pointer = const value_type*;
        using iterator = value_type*;
        using const_iterator = const value_type*;

        /**
         * size of the string in bytes
         */
        uint16_t size_;
        wchar_t string_[1];

        const_pointer string() const
        {
            return string_;
        }

        size_t length() const
        {
            return size_ / sizeof(value_type);
        }
    };
#pragma pack(pop)

    static_assert(std::is_trivial<counted_string>::value && std::is_standard_layout<counted_string>::value , "Do not modify counted_string");

} /* namespace krabs */
