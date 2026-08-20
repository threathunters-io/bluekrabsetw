// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <cstdint>
#include <string>
#include <type_traits>
#include <windows.h>

#include "compiler_check.hpp"

namespace krabs {

    /**
     * <summary>
     * Position-independent view types over an ETW record's property bytes.
     * Each type is structurally {offset, length} but nominally distinct so
     * codegen can select the right type per schema property and callers get
     * type-safe accessors.
     * </summary>
     * <remarks>
     * A view holds only offset + length. To read the actual bytes call
     * data(base) with a pointer to the record's UserData (or an arena-copied
     * equivalent). Views survive memcpy of the underlying bytes; the same
     * view against a different base produces the correct pointer.
     *
     * Design contract: every view type is exactly 8 bytes, trivially
     * copyable, and standard-layout — the x64 ABI returns such types in a
     * single register (RAX). Pass and return of a view compile to one mov.
     * The static_asserts below make this a hard invariant; any future change
     * that grows the type or adds non-trivial members will fail to compile.
     * </remarks>
     */

    namespace detail {

        // Common base for all offset+length view types.
        // 8 bytes exactly, trivially copyable, standard layout.
        struct byte_range {
            ULONG offset;
            ULONG length;

            constexpr byte_range() noexcept : offset(0), length(0) {}
            constexpr byte_range(ULONG off, ULONG len) noexcept : offset(off), length(len) {}

            constexpr bool empty() const noexcept { return length == 0; }

            // Raw byte access. Callers with a typed view should prefer the
            // typed accessor (e.g. wstring_view::c_str(base)).
            const BYTE* data(const BYTE* base) const noexcept {
                return base + offset;
            }
        };

    } // namespace detail

    // Unicode string view. Length is in BYTES (not chars). String may or may
    // not be null-terminated depending on ETW encoding.
    struct wstring_view : detail::byte_range {
        using detail::byte_range::byte_range;

        // Pointer to the first wchar_t of the string.
        const wchar_t* c_str(const BYTE* base) const noexcept {
            return reinterpret_cast<const wchar_t*>(data(base));
        }

        // Length in characters (not bytes).
        constexpr size_t char_count() const noexcept {
            return length / sizeof(wchar_t);
        }

        // Materialize as std::wstring. Allocates; use sparingly on hot paths.
        std::wstring to_wstring(const BYTE* base) const {
            return std::wstring(c_str(base), char_count());
        }
    };

    // ANSI string view. Length is in BYTES.
    struct string_view : detail::byte_range {
        using detail::byte_range::byte_range;

        const char* c_str(const BYTE* base) const noexcept {
            return reinterpret_cast<const char*>(data(base));
        }

        std::string to_string(const BYTE* base) const {
            return std::string(c_str(base), length);
        }
    };

    // SID view. Bytes point at a Windows SID structure or a WBEMSID wrapper.
    // Interpretation (SID vs WBEMSID) requires the schema's InType.
    struct sid_view : detail::byte_range {
        using detail::byte_range::byte_range;
    };

    // Binary blob view. Length is in BYTES.
    struct binary_view : detail::byte_range {
        using detail::byte_range::byte_range;

        const BYTE* begin(const BYTE* base) const noexcept { return data(base); }
        const BYTE* end  (const BYTE* base) const noexcept { return data(base) + length; }
    };

    // Counted-string view. Wire format is [uint16 byte-length][wchar_t data...].
    // length covers the entire on-wire payload including the size prefix.
    struct counted_string_view : detail::byte_range {
        using detail::byte_range::byte_range;
    };

    // Socket address view. Bytes point at a sockaddr / sockaddr_in / sockaddr_in6
    // depending on the schema.
    struct socket_address_view : detail::byte_range {
        using detail::byte_range::byte_range;
    };

    // -----------------------------------------------------------------------
    // Register-copy contract: every view must be 8 bytes, trivially copyable,
    // and standard-layout so the x64 ABI can return it in a single register.
    // -----------------------------------------------------------------------

    #define KRABS_ASSERT_VIEW_ABI(T)                                           \
        static_assert(sizeof(T) == 8,                                          \
                      #T " must be 8 bytes for register-copy return");        \
        static_assert(std::is_trivially_copyable<T>::value,                    \
                      #T " must be trivially copyable");                       \
        static_assert(std::is_standard_layout<T>::value,                       \
                      #T " must be standard layout")

    KRABS_ASSERT_VIEW_ABI(detail::byte_range);
    KRABS_ASSERT_VIEW_ABI(wstring_view);
    KRABS_ASSERT_VIEW_ABI(string_view);
    KRABS_ASSERT_VIEW_ABI(sid_view);
    KRABS_ASSERT_VIEW_ABI(binary_view);
    KRABS_ASSERT_VIEW_ABI(counted_string_view);
    KRABS_ASSERT_VIEW_ABI(socket_address_view);

    #undef KRABS_ASSERT_VIEW_ABI

} // namespace krabs
