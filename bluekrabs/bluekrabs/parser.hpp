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
        parser(const schema&);

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
        bool try_parse(const std::wstring& name, T& out, ULONG& index);

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
        bool try_parse(const std::wstring& name, T& out);

        /**
         * <summary>
         * Attempts to parse the given property by name and type. If the
         * property does not exist, an exception is thrown.
         * </summary>
         */
        template <typename T>
        T parse(const std::wstring& name, ULONG& index);

        /**
         * <summary>
         * Attempts to parse the given property by name and type. If the
         * property does not exist, an exception is thrown.
         * </summary>
         */
        template <typename T>
        T parse(const std::wstring& name);

        /**
        * todo
        */
        std::pair<const char*, _TDH_IN_TYPE> parse_in_type(const std::wstring& name);

        /**
        * todo
        */
        std::pair<const char*, _TDH_OUT_TYPE> parse_out_type(const std::wstring& name);

        template <typename Adapter>
        auto view_of(const std::wstring& name, Adapter& adapter) -> collection_view<typename Adapter::const_iterator>;

    private:
        property_info find_property(const std::wstring& name);
        property_info find_property_at(ULONG index);

        inline property_info resolve_property(const std::wstring& name, ULONG index)
        {
            return (index != npos) ? find_property_at(index) : find_property(name);
        }

        // Resolve a target property's offset+length by summing known lengths
        // from the two caches, only invoking size_provider for dynamic
        // properties whose per-event length isn't already resolved.
        // No mutation of parser cursor state.
        property_info resolve_offset(ULONG target);

        // Per-event tail-offset storage. Sparse: only indices in the range
        // [layout_fixed_snapshot_, PropertyCount) have slots. Access with
        // offset_slot(global_index).
        //   - If tail_count_ <= kInlineTail: inline storage on the parser
        //     itself, zero heap allocation.
        //   - Else: falls back to heap_offsets_.
        // Callers must only invoke offset_slot() for indices past the fixed
        // prefix snapshot; fixed-prefix reads hit layout.entries directly.
        static constexpr size_t kInlineTail = 8;

        inline property_info& offset_slot(ULONG global_i)
        {
            ULONG local = global_i - layout_fixed_snapshot_;
            return (tail_count_ <= kInlineTail)
                ? inline_offsets_[local]
                : heap_offsets_[local];
        }

        inline const property_info& offset_slot(ULONG global_i) const
        {
            ULONG local = global_i - layout_fixed_snapshot_;
            return (tail_count_ <= kInlineTail)
                ? inline_offsets_[local]
                : heap_offsets_[local];
        }

    private:
        const schema& schema_;
        const BYTE* pUserData_;      // base pointer for property_info::pointer_in()
        const BYTE* pEndBuffer_;

        // Snapshot of layout.fixed_count at parser construction. All indices
        // >= snapshot land in offset_slot(); < snapshot is served directly
        // from layout.entries.
        ULONG layout_fixed_snapshot_;
        ULONG tail_count_;

        property_info              inline_offsets_[kInlineTail];
        std::vector<property_info> heap_offsets_;   // used only if tail_count_ > kInlineTail
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline parser::parser(const schema& s)
        : schema_(s)
        , pUserData_((const BYTE*)s.record_.UserData)
        , pEndBuffer_(pUserData_ + s.record_.UserDataLength)
        , layout_fixed_snapshot_(s.layout().fixed_count)
        , tail_count_(s.pSchema_->PropertyCount > layout_fixed_snapshot_
            ? s.pSchema_->PropertyCount - layout_fixed_snapshot_
            : 0)
    {
        // Reset tail slots to default (all npos). Inline storage may hold
        // stale values from a previous parser on this stack frame, so we must
        // reinitialize the portion we'll use.
        if (tail_count_ <= kInlineTail) {
            for (ULONG i = 0; i < tail_count_; ++i) {
                inline_offsets_[i] = property_info();
            }
        }
        else {
            heap_offsets_.assign(tail_count_, property_info{});
        }
    }

    inline property_iterator parser::properties() const
    {
        return property_iterator(schema_);
    }

    // Compute the property_info for `target` by summing lengths from index 0
    // upward. Uses the two caches to avoid re-doing work:
    //   - fixed prefix: length_ from layout.entries[j].
    //   - past prefix, schema-fixed length: length_ from layout.entries[j].
    //   - past prefix, resolved this event: length_ from offset_slot(j).
    //   - past prefix, dynamic + unresolved: one size_provider byte-scan.
    // Populates offset_slot() for every property visited past the fixed
    // prefix; populates layout.entries / fixed_count / name_index on first
    // sight of the descriptor.
    inline property_info parser::resolve_offset(ULONG target)
    {
        auto& layout = schema_.layout();
        ULONG cursor = 0;

        // Start from wherever the layout's fixed prefix ends. Fixed prefix
        // offsets are already correct in layout.entries; we just need the
        // running cursor to continue past them.
        ULONG j = layout.fixed_count;
        if (j > 0) cursor = layout.prefix_byte_end;

        // The target itself may be in the fixed prefix — return directly.
        if (target < layout.fixed_count) return layout.entries[target];

        while (j <= target) {
            auto& layout_entry = layout.entries[j];

            ULONG len;
            if (layout_entry.has_length()) {
                // Fast path: schema-fixed length already cached. Nothing to write.
                len = layout_entry.length_;

                // Still need to check if this iteration extends the fixed prefix.
                // (Could be schema-fixed but offset not yet cached — first-sight case.)
                if (j == layout.fixed_count) {
                    layout_entry.offset_ = cursor;
                    layout.fixed_count = j + 1;
                    layout.prefix_byte_end = cursor + len;
                }
                else if (j >= layout_fixed_snapshot_) {
                    // Past our snapshot's fixed prefix. Cache per-event.
                    offset_slot(j) = property_info(cursor, len, j);
                }
            }
            else {
                // Slow path: length not in layout. Either per-event cache or byte-scan.
                auto& currentPropInfo = schema_.pSchema_->EventPropertyInfoArray[j];

                if (j >= layout_fixed_snapshot_ && offset_slot(j).found()) {
                    len = offset_slot(j).length_;
                }
                else {
                    const wchar_t* pName = reinterpret_cast<const wchar_t*>(
                        reinterpret_cast<BYTE*>(schema_.pSchema_) + currentPropInfo.NameOffset);
                    len = size_provider::get_property_size(
                        pUserData_ + cursor, pName, schema_.record_, currentPropInfo);
                }

                if (pUserData_ + cursor + len > pEndBuffer_) {
                    throw std::out_of_range("Property length past end of property buffer");
                }

                // Check for schema-fixed status only in this path (dynamic-or-first-sight
                // property). If it turns out to be schema-fixed, cache the length.
                const bool schema_fixed =
                    (currentPropInfo.Flags & (PropertyParamLength | PropertyParamCount)) == 0
                    && currentPropInfo.length > 0;

                if (schema_fixed) {
                    layout_entry.length_ = len;
                    layout_entry.property_index_ = j;
                    if (j == layout.fixed_count) {
                        layout_entry.offset_ = cursor;
                        layout.fixed_count = j + 1;
                        layout.prefix_byte_end = cursor + len;
                    }
                }

                // Per-event cache for anything past our snapshot's fixed prefix.
                if (j >= layout_fixed_snapshot_) {
                    offset_slot(j) = property_info(cursor, len, j);
                }
            }

            if (j == target) return property_info(cursor, len, j);

            // Name -> index cache. Only for slow-path visits where we may not have
            // seen this index before. In fast-path we've been here before (length
            // came from layout, which is populated only after a walk).
            if (layout.name_index.size() <= j) {
                auto& currentPropInfo = schema_.pSchema_->EventPropertyInfoArray[j];
                const wchar_t* pName = reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<BYTE*>(schema_.pSchema_) + currentPropInfo.NameOffset);
                layout.name_index.push_back({ pName, j });
            }

            cursor += len;
            ++j;
        }

        return property_info();
    }

    inline property_info parser::find_property(const std::wstring& name)
    {
        // A schema contains a collection of properties keyed by name. Property
        // bytes are stored in a blob that requires linear traversal because
        // variable-length properties have no on-wire offset. We minimize this
        // via three caches:
        //   - per-descriptor layout.entries:    schema-fixed offsets + lengths.
        //   - per-descriptor layout.name_index: name -> index resolutions.
        //   - per-event offset_slot():          everything resolved in this event (tail only).
        //
        // Single pass: use cached name pointer when this index has been seen
        // before, otherwise resolve from the schema and remember it. name_index
        // grows monotonically from index 0, so a simple size() check partitions
        // known indices from new ones with no gaps.

        auto& layout = schema_.layout();
        const ULONG totalPropCount = schema_.pSchema_->PropertyCount;

        for (ULONG i = 0; i < totalPropCount; ++i) {
            const wchar_t* pName;
            if (i < layout.name_index.size()) {
                pName = layout.name_index[i].name;
            }
            else {
                pName = reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<BYTE*>(schema_.pSchema_) +
                    schema_.pSchema_->EventPropertyInfoArray[i].NameOffset);
                layout.name_index.push_back({ pName, i });
            }

            if (name == pName) {
                return find_property_at(i);
            }
        }
        return property_info();
    }

    inline property_info parser::find_property_at(ULONG index)
    {
        auto& layout = schema_.layout();
        const ULONG totalPropCount = schema_.pSchema_->PropertyCount;
        if (index >= totalPropCount) return property_info();

        // Fast path 1: fully cached in layout (fixed prefix).
        if (index < layout.fixed_count) return layout.entries[index];

        // Fast path 2: already resolved for this event (tail only).
        if (index >= layout_fixed_snapshot_ && offset_slot(index).found()) {
            return offset_slot(index);
        }

        // Compute directly by summing known lengths.
        return resolve_offset(index);
    }

    inline void throw_if_property_not_found(const property_info& propInfo)
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

        T nullChar{ 0 };
        auto length = lengthBytes / sizeof(T);

        for (auto i = length; i >= 1; --i)
            if (string[i - 1] != nullChar) return i;

        return 0;
    }

    // try_parse
    // ------------------------------------------------------------------------

    template <typename T>
    bool parser::try_parse(const std::wstring& name, T& out, ULONG& index)
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
    bool parser::try_parse(const std::wstring& name, T& out)
    {
        ULONG index = npos;
        return try_parse<T>(name, out, index);
    }

    // parse
    // ------------------------------------------------------------------------

    template <typename T>
    T parser::parse(const std::wstring& name)
    {
        ULONG index = npos;
        return parse<T>(name, index);
    }

    template <typename T>
    T parser::parse(const std::wstring& name, ULONG& index)
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
    inline std::wstring parser::parse<std::wstring>(const std::wstring& name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<std::wstring>(name, propInfo, schema_.pSchema_);

        auto string = reinterpret_cast<const wchar_t*>(propInfo.pointer_in(pUserData_));
        auto length = get_string_content_length(string, propInfo.length_);

        return std::wstring(string, length);
    }

    template <>
    inline std::string parser::parse<std::string>(const std::wstring& name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<std::string>(name, propInfo, schema_.pSchema_);

        auto string = reinterpret_cast<const char*>(propInfo.pointer_in(pUserData_));
        auto length = get_string_content_length(string, propInfo.length_);

        return std::string(string, length);
    }

    template<>
    inline const counted_string* parser::parse<const counted_string*>(const std::wstring& name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        krabs::debug::assert_valid_assignment<const counted_string*>(name, propInfo, schema_.pSchema_);

        return reinterpret_cast<const counted_string*>(propInfo.pointer_in(pUserData_));
    }

    template<>
    inline binary parser::parse<binary>(const std::wstring& name, ULONG& index)
    {
        auto propInfo = resolve_property(name, index);
        throw_if_property_not_found(propInfo);

        // no type asserts for binary - anything can be read as binary

        return binary(propInfo.pointer_in(pUserData_), propInfo.length_);
    }

    template<>
    inline ip_address parser::parse<ip_address>(
        const std::wstring& name, ULONG& index)
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
        const std::wstring& name, ULONG& index)
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
    auto parser::view_of(const std::wstring& name, Adapter& adapter)
        -> collection_view<typename Adapter::const_iterator>
    {
        auto propInfo = find_property(name);
        throw_if_property_not_found(propInfo);

        // TODO: type asserts?

        return adapter(propInfo, pUserData_);
    }
}
