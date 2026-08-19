// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <cassert>
#include <utility>
#include <stdexcept>
#include <vector>

#include <functional>

#include "compiler_check.hpp"
#include "collection_view.hpp"
#include "property.hpp"
#include "parse_types.hpp"
#include "size_provider.hpp"
#include "tdh_helpers.hpp"

namespace krabs {

    class schema;

    /**
     * <summary>
     * Used to parse specific properties out of an event schema.
     * </summary>
     * <remarks>
     * The parser class dodges the task of trying to validate that the expected
     * type of a field matches the actual type of a field -- the onus is on
     * client code to get this right.
     * </remarks>
     */
    class parser {
    public:

        static constexpr ULONG npos = ULONG(-1);
        /**
         * <summary>
         * Constructs an event parser from an event schema.
         * </summary>
         * <example>
         *     void on_event(const EVENT_RECORD &record)
         *     {
         *         krabs::schema schema(record);
         *         krabs::parser parser(schema);
         *     }
         * </example>
         */
        parser(const schema &);

        /**
         * <summary>
         * Returns an iterator that returns each property in the event.
         * </summary>
         * <example>
         *    void on_event(const EVENT_RECORD &record)
         *    {
         *        krabs::schema schema(record);
         *        krabs::parser parser(schema);
         *        for (property &property : parser.properties())
         *        {
         *            // ...
         *        }
         *    }
         * </example>
         */
        property_iterator properties() const;

        /**
         * <summary>
         * Attempts to retrieve the given property by name and type.
         * </summary>
         * <remarks>
         * Type hinting here is taken as the authoritative source. There is no
         * validation that the request for type is correct.
         * </remarks>
         */
        template <typename T>
        bool try_parse(const std::wstring &name, T &out, ULONG& index);

        /**
         * <summary>
         * Attempts to retrieve the given property by name and type.
         * </summary>
         * <remarks>
         * Type hinting here is taken as the authoritative source. There is no
         * validation that the request for type is correct.
         * </remarks>
         */
        template <typename T>
        bool try_parse(const std::wstring &name, T &out);

        /**
         * <summary>
         * Attempts to parse the given property by name and type. If the
         * property does not exist, an exception is thrown.
         * </summary>
         */
        template <typename T>
        T parse(const std::wstring &name, ULONG& index);

        /**
         * <summary>
         * Attempts to parse the given property by name and type. If the
         * property does not exist, an exception is thrown.
         * </summary>
         */
        template <typename T>
        T parse(const std::wstring &name);

        /**
        * todo
        */
        std::pair<const char*, _TDH_IN_TYPE> parse_in_type(const std::wstring& name);

        /**
        * todo
        */
        std::pair<const char*, _TDH_OUT_TYPE> parse_out_type(const std::wstring& name);

        template <typename Adapter>
        auto view_of(const std::wstring &name, Adapter &adapter) -> collection_view<typename Adapter::const_iterator>;

    private:
        property_info find_property(const std::wstring &name);
        property_info find_property_at(ULONG index);

        inline property_info resolve_property(const std::wstring& name, ULONG index)
        {
            return (index != npos) ? find_property_at(index) : find_property(name);
        }

    private:
        const schema &schema_;
        const BYTE *pUserData_;      // base pointer for property_info::pointer_in()
        const BYTE *pEndBuffer_;
        BYTE *pBufferIndex_;
        ULONG lastPropertyIndex_;

        // Per-event property offsets. Sized at construction to schema's
        // PropertyCount. Fixed-prefix slots (indices < layout.fixed_count)
        // stay default-npos — reads for those hit the shared layout cache.
        // Tail slots (>= fixed_count) fill as the parser walks.
        std::vector<property_info> perEventOffsets_;
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline parser::parser(const schema &s)
    : schema_(s)
    , pUserData_((const BYTE*)s.record_.UserData)
    , pEndBuffer_(pUserData_ + s.record_.UserDataLength)
    , pBufferIndex_((BYTE*)s.record_.UserData)
    , lastPropertyIndex_(0)
    , perEventOffsets_(s.pSchema_->PropertyCount)
    {}

    inline property_iterator parser::properties() const
    {
        return property_iterator(schema_);
    }

    inline property_info parser::find_property(const std::wstring &name)
    {
        // A schema contains a collection of properties keyed by name. Property
        // bytes are stored in a blob that requires linear traversal because
        // variable-length properties have no on-wire offset. We minimize this
        // via two caches:
        //   - per-descriptor schema.layout(): schema-fixed offsets + lengths.
        //   - per-event perEventOffsets_:     everything walked in this event.

        auto& layout = schema_.layout();
        const ULONG totalPropCount = schema_.pSchema_->PropertyCount;

        assert((pBufferIndex_ <= pEndBuffer_ && pBufferIndex_ >= schema_.record_.UserData) &&
               "invariant: we should've already thrown for falling off the edge");

        // accept that last property can be omitted from buffer. this happens if last property
        // is string but empty and the provider strips the null terminator
        assert((pBufferIndex_ == pEndBuffer_ ? ((totalPropCount - lastPropertyIndex_) <= 1)
                                             : true)
               && "invariant: if we've exhausted our buffer, then we must've"
                  "exhausted the properties as well");

        for (auto &i = lastPropertyIndex_; i < totalPropCount; ++i) {

            auto &currentPropInfo = schema_.pSchema_->EventPropertyInfoArray[i];
            const wchar_t *pName = reinterpret_cast<const wchar_t*>(
                                        reinterpret_cast<BYTE*>(schema_.pSchema_) +
                                        currentPropInfo.NameOffset);

            // Length: use layout cache if schema-fixed and already resolved,
            // otherwise consult size_provider (walks bytes for dynamic props).
            ULONG propertyLength;
            {
                auto& cached = layout.entries[i];
                if (cached.has_length()) {
                    propertyLength = cached.length_;
                } else {
                    propertyLength = size_provider::get_property_size(
                                        pBufferIndex_, pName,
                                        schema_.record_, currentPropInfo);
                }
            }

            // verify that the length of the property doesn't exceed the buffer
            if (pBufferIndex_ + propertyLength > pEndBuffer_) {
                throw std::out_of_range("Property length past end of property buffer");
            }

            const ULONG offset = ULONG(pBufferIndex_ - pUserData_);
            property_info propInfo(offset, propertyLength, i);

            // Populate the per-descriptor layout:
            //   - length: cache whenever the schema fixes it (same predicate
            //     size_provider uses for its fixed-length short-circuit).
            //   - offset: cache only while every prior property has fixed
            //     length, i.e. i == layout.fixed_count.
            const bool schema_fixed =
                (currentPropInfo.Flags & (PropertyParamLength | PropertyParamCount)) == 0
                && currentPropInfo.length > 0;

            auto& cached = layout.entries[i];
            if (schema_fixed && !cached.has_length()) {
                cached.length_ = propertyLength;
                cached.property_index_ = i;
            }
            if (i == layout.fixed_count && cached.has_length()) {
                cached.offset_ = offset;
                layout.fixed_count = i + 1;
                layout.prefix_byte_end = offset + propertyLength;
            }

            // Per-event cache: only tail entries; fixed-prefix reads go
            // straight to layout in find_property_at.
            if (i >= layout.fixed_count) {
                perEventOffsets_[i] = propInfo;
            }

            // advance the buffer index since we've already processed this property
            pBufferIndex_ += propertyLength;

            // The property was found, return it
            if (name == pName) {
                // advance the index since we've already processed this property
                ++i;
                return propInfo;
            }
        }

        // property wasn't found, return an empty propInfo
        return property_info();
    }

    inline property_info parser::find_property_at(ULONG index)
    {
        auto& layout = schema_.layout();
        const ULONG totalPropCount = schema_.pSchema_->PropertyCount;
        if (index >= totalPropCount)
            return property_info();

        // Fast path 1: descriptor cache has full offset+length (fixed prefix).
        if (index < layout.fixed_count) {
            return layout.entries[index];
        }

        // Fast path 2: this parser already walked past `index` in this event.
        if (perEventOffsets_[index].found()) {
            return perEventOffsets_[index];
        }

        // Slow path: walk from cursor to `index`, filling both caches.
        for (auto& i = lastPropertyIndex_; i <= index && i < totalPropCount; ++i)
        {
            auto& currentPropInfo = schema_.pSchema_->EventPropertyInfoArray[i];
            const wchar_t* pName = reinterpret_cast<const wchar_t*>(
                reinterpret_cast<BYTE*>(schema_.pSchema_) +
                currentPropInfo.NameOffset);

            ULONG propertyLength;
            {
                auto& cached = layout.entries[i];
                if (cached.has_length()) {
                    propertyLength = cached.length_;
                } else {
                    propertyLength = size_provider::get_property_size(
                        pBufferIndex_, pName, schema_.record_, currentPropInfo);
                }
            }

            if (pBufferIndex_ + propertyLength > pEndBuffer_)
                throw std::out_of_range("Property length past end of property buffer");

            const ULONG offset = ULONG(pBufferIndex_ - pUserData_);
            property_info propInfo(offset, propertyLength, i);

            const bool schema_fixed =
                (currentPropInfo.Flags & (PropertyParamLength | PropertyParamCount)) == 0
                && currentPropInfo.length > 0;

            auto& cached = layout.entries[i];
            if (schema_fixed && !cached.has_length()) {
                cached.length_ = propertyLength;
                cached.property_index_ = i;
            }
            if (i == layout.fixed_count && cached.has_length()) {
                cached.offset_ = offset;
                layout.fixed_count = i + 1;
                layout.prefix_byte_end = offset + propertyLength;
            }

            if (i >= layout.fixed_count) {
                perEventOffsets_[i] = propInfo;
            }

            pBufferIndex_ += propertyLength;

            if (i == index)
            {
                ++i;
                return propInfo;
            }
        }

        return property_info();
    }

    inline void throw_if_property_not_found(const property_info &propInfo)
    {
        if (!propInfo.found()) {
            throw std::runtime_error("Property with the given name does not exist");
        }
    }

    template <typename T>
    size_t get_string_content_length(const T* string, size_t lengthBytes)
    {
        // for some string types the length includes the null terminator
        // so we need to find the length of just the content part

        T nullChar {0};
        auto length = lengthBytes / sizeof(T);

        for (auto i = length; i >= 1; --i)
            if (string[i - 1] != nullChar) return i;

        return 0;
    }

    // try_parse
    // ------------------------------------------------------------------------

    template <typename T>
    bool parser::try_parse(const std::wstring &name, T &out, ULONG& index)
    {
        try {
            out = parse<T>(name, index);
            return true;
        }

#ifndef NDEBUG
        // in debug builds we want any mismatch asserts
        // to get back to the caller. This is removed
        // in release builds.
        catch (const krabs::type_mismatch_assert&) {
            throw;
        }
#endif // NDEBUG

        catch (...) {
            return false;
        }
    }

    template <typename T>
    bool parser::try_parse(const std::wstring &name, T &out)
    {
        ULONG index = npos;
        return try_parse<T>(name, out, index);
    }

    // parse
    // ------------------------------------------------------------------------

    template <typename T>
    T parser::parse(const std::wstring &name)
    {
        ULONG index = npos;
        return parse<T>(name, index);
    }

    template <typename T>
    T parser::parse(const std::wstring &name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<T>(name, propInfo, schema_.pSchema_);

        // ensure that size of the type we are requesting is
        // the same size of the property in the event
        if (sizeof(T) != propInfo.length_)
            throw std::runtime_error("Property size doesn't match requested size");

        return *(T*)propInfo.pointer_in(pUserData_);
    }

    template<>
    inline bool parser::parse<bool>(const std::wstring& name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<bool>(name, propInfo, schema_.pSchema_);

        // Boolean in ETW is 4 bytes long
        return static_cast<bool>(*(unsigned*)propInfo.pointer_in(pUserData_));
    }

    template <>
    inline std::wstring parser::parse<std::wstring>(const std::wstring &name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<std::wstring>(name, propInfo, schema_.pSchema_);

        auto string = reinterpret_cast<const wchar_t*>(propInfo.pointer_in(pUserData_));
        auto length = get_string_content_length(string, propInfo.length_);

        return std::wstring(string, length);
    }

    template <>
    inline std::string parser::parse<std::string>(const std::wstring &name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<std::string>(name, propInfo, schema_.pSchema_);

        auto string = reinterpret_cast<const char*>(propInfo.pointer_in(pUserData_));
        auto length = get_string_content_length(string, propInfo.length_);

        return std::string(string, length);
    }

    template<>
    inline const counted_string* parser::parse<const counted_string*>(const std::wstring &name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<const counted_string*>(name, propInfo, schema_.pSchema_);

        return reinterpret_cast<const counted_string*>(propInfo.pointer_in(pUserData_));
    }

    template<>
    inline binary parser::parse<binary>(const std::wstring &name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        // no type asserts for binary - anything can be read as binary

        return binary(propInfo.pointer_in(pUserData_), propInfo.length_);
    }

    template<>
    inline ip_address parser::parse<ip_address>(
        const std::wstring &name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<ip_address>(name, propInfo, schema_.pSchema_);

        auto outType = propInfo.info_in(schema_.pSchema_).nonStructType.OutType;

        switch (outType) {
        case TDH_OUTTYPE_IPV6:
            return ip_address::from_ipv6(propInfo.pointer_in(pUserData_));

        case TDH_OUTTYPE_IPV4:
            return ip_address::from_ipv4(*(DWORD*)propInfo.pointer_in(pUserData_));

        default:
            throw std::runtime_error("IP Address was not IPV4 or IPV6");
        }
    }

    template<>
    inline socket_address parser::parse<socket_address>(
        const std::wstring &name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<socket_address>(name, propInfo, schema_.pSchema_);

        return socket_address::from_bytes(propInfo.pointer_in(pUserData_), propInfo.length_);
    }

    template<>
    inline sid parser::parse<sid>(
        const std::wstring& name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<sid>(name, propInfo, schema_.pSchema_);
        auto InType = propInfo.info_in(schema_.pSchema_).nonStructType.InType;

        // A WBEMSID is actually a TOKEN_USER structure followed by the SID.
        // We only care about the SID. From MSDN:
        //
        //      The size of the TOKEN_USER structure differs
        //      depending on whether the events were generated on a 32 - bit
        //      or 64 - bit architecture. Also the structure is aligned
        //      on an 8 - byte boundary, so its size is 8 bytes on a
        //      32 - bit computer and 16 bytes on a 64 - bit computer.
        //      Doubling the pointer size handles both cases.
        ULONG sid_start = 16;
        if (EVENT_HEADER_FLAG_32_BIT_HEADER == (schema_.record_.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER)) {
            sid_start = 8;
        }
        switch (InType) {
        case TDH_INTYPE_SID:
            return sid::from_bytes(propInfo.pointer_in(pUserData_), propInfo.length_);
        case TDH_INTYPE_WBEMSID:
            // Safety measure to make sure we don't overflow
            if (propInfo.length_ <= sid_start) {
                throw std::runtime_error(
                    "Requested a WBEMSID property but data is too small");
            }
            return sid::from_bytes(propInfo.pointer_in(pUserData_) + sid_start, propInfo.length_ - sid_start);

        default:
            throw std::runtime_error("SID was not a SID or WBEMSID");
        }
    }

    template<>
    inline pointer parser::parse<pointer>(const std::wstring& name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<pointer>(name, propInfo, schema_.pSchema_);

        return pointer::from_bytes(propInfo.pointer_in(pUserData_), propInfo.length_);
    }

    // pars_type
    // ------------------------------------------------------------------------

    inline std::pair<const char*, _TDH_IN_TYPE> parser::parse_in_type(const std::wstring& name)
    {
        auto prop_info = find_property(name);
        throw_if_property_not_found(prop_info);

        auto in_type_value = (_TDH_IN_TYPE)prop_info.info_in(schema_.pSchema_).nonStructType.OutType;
        auto in_type_str = in_type_to_string(in_type_value);

        return std::make_pair(in_type_str, in_type_value);
    }

    inline std::pair<const char*, _TDH_OUT_TYPE> parser::parse_out_type(const std::wstring& name)
    {
        auto prop_info = find_property(name);
        throw_if_property_not_found(prop_info);

        auto out_type_value = (_TDH_OUT_TYPE)prop_info.info_in(schema_.pSchema_).nonStructType.OutType;
        auto out_type_str = out_type_to_string(out_type_value);

        return std::make_pair(out_type_str, out_type_value);
    }


    // view_of
    // ------------------------------------------------------------------------

    template <typename Adapter>
    auto parser::view_of(const std::wstring &name, Adapter &adapter)
        -> collection_view<typename Adapter::const_iterator>
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        // TODO: type asserts?

        return adapter(propInfo, pUserData_);
    }
}
