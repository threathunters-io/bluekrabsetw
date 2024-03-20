#pragma once
#include <string>
#include <vector>
#include <map>

//Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEA
#include <windows.h>
#include <combaseapi.h>
#include <tdh.h>
#pragma comment(lib, "tdh")

#include "helping/file_mapping.hpp"
//#include "common.hpp"
//#include "output_cache.hpp"

namespace krabs {
	struct resource_metadata {
		std::wstring name;
		DWORD size{ NULL };
		BYTE* address{ nullptr };
		DWORD rva{ NULL };
	};

	class wevt : file_mapping {
	public:
		wevt(
			const std::wstring& path,
			utility::binary_memory_mapping_c& binary_mem_map,
			utility::output_cache_c& output_cache);

		~wevt();

		open(const std::wstring& path);
		

		bool signatur_found();
		bool push_to_cache(const bool& is_dump = false);

	protected:

	private:
		bool enum_events();
		bool find_resource(const std::wstring& path);
		TDHSTATUS record_at(const int& at, common::record_s& record);

		//file_mapping file_mapping_;

		utility::binary_memory_mapping& binary_mem_map_;
		utility::output_cache_c& output_cache_;

		HMODULE module_handle_{ NULL };
		HRSRC wevt_resource_handle_{ NULL };
		resource_metadata resource_;

		std::wstring path_;
		bool resource_found_{ false };
		bool provider_info_found_{ false };

		GUID* guid_{ nullptr };
		std::wstring guid_wstr_;
		std::wstring provider_name_;
		PROVIDER_EVENT_INFO* event_info_{ nullptr };
		std::vector<BYTE> event_info_buffer_;
		ULONG event_info_size_{ 0 };
	};


	// Implementation
	// ------------------------------------------------------------------------

	wevt::wevt(
		const std::wstring& path,
		utility::binary_memory_mapping_c& binary_mem_map,
		utility::output_cache_c& output_cache)
		: path_(path)
		, binary_mem_map_(binary_mem_map)
		, output_cache_(output_cache)
	{

		if (path.empty())
			throw std::exception("wevt_metadata_c::wevt_metadata_c: path empty");

		if (resource_found_ = find_resource()) {
			provider_info_found_ = init_provider_info();
		}

	}

	wevt::~wevt() 
	{
		if (!m_module_handle_) {
			::FreeLibrary(m_module_handle_);
		}
	}

	bool wevt::open(const std::wstring& path)
	{
		bool status = false;

		if ((status = this->create_mapping(path)) == 0) {
			return status;
		}

		if ((status = find_resource(path)) == 0) {
			return status;
		}

		if ((status = enum_events()) == 0) {
			return status;
		}

		return status;
	}

	bool wevt::find_resource(const std::wstring& path)
	{
		bool status{ false };

		if (module_handle_ == NULL)
			module_handle_ = ::LoadLibraryEx(path.c_str(), nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);

		if (module_handle_ != NULL) {
			const std::wstring resource_name{ L"WEVT_TEMPLATE" };
			resource_handle_ = ::FindResource(module_handle_, MAKEINTRESOURCE(1), resource_name.c_str());

			if (resource_handle_) {
				resource_.name = resource_name;
				resource_.size = ::SizeofResource(module_handle_, resource_handle_);
				resource_.address = (BYTE*)::LockResource(::LoadResource(module_handle_, resource_handle_));
				resource_.rva = static_cast<DWORD>(DWORD_PTR(resource_.address) - (DWORD_PTR(module_handle_) & ~0xf));

				status = true;
			}
		}

		return status;
	}

	bool wevt::enum_events() 
	{
		TDHSTATUS status{ (ULONG)-1 };
		wchar_t guid_wstr[64];

		if (resource_found_) {
			guid_ = resource_.address == nullptr ? nullptr : (GUID*)(((PBYTE)resource_.address) + 16);

			if (guid_ != nullptr) {
				::StringFromGUID2(*guid_, guid_wstr, _countof(guid_wstr));
				guid_wstr_ = guid_wstr;

				status = ::TdhLoadManifestFromBinary((PWSTR)path_.c_str());
				if (status != ERROR_SUCCESS) { goto exit; }

				do {
					if (status == ERROR_INSUFFICIENT_BUFFER) {
						try {
							event_info_buffer_.resize(event_info_size_);
							event_info_ = (PROVIDER_EVENT_INFO*)&event_info_buffer_.at(0);
							status = ERROR_SUCCESS;
						}
						catch (std::bad_alloc) {
							status = ERROR_OUTOFMEMORY;
						}
					}

					status = ::TdhEnumerateManifestProviderEvents(guid_, event_info_, &event_info_size_);
				} while (status == ERROR_INSUFFICIENT_BUFFER);
			}
		}

	exit:
		return status == ERROR_SUCCESS;
	}

	bool wevt::push_to_cache(const bool& is_dump /* = false */) 
	{
		if (event_info_ == nullptr) {
			throw std::exception("wevt_metadata_c::push_to_cache: mp_provider_info_ nullptr");
		}

		TDHSTATUS status{ (ULONG)-1 };

		if (resource_found_ && provider_info_found_) {
			if (event_info_->NumberOfEvents != 0) {
				std::map<common::provider_type_e, common::provider_s> buffer;
				common::provider_s provider;
				provider.type = common::provider_type_e::wevt;

				if (!is_dump) {
					common::record_s record;
					status = record_at(0, record);

					if (status == ERROR_SUCCESS) {
						auto pair = std::make_pair(provider_name_, guid_wstr_);
						provider.m_identifiers.emplace(pair);
						buffer.emplace(common::provider_type_e::wevt, provider);
						output_cache_.push(path_, buffer);
					}

				}
				else {
					for (unsigned int at = 0; at < event_info_->NumberOfEvents; at++) {
						common::record_s record;
						status = record_at(at, record);

						if (status == ERROR_SUCCESS) {
							provider.records.push_back(record);
						}
					}

					auto pair = std::make_pair(provider_name_, guid_wstr_);
					provider.identifiers.emplace(pair);
					buffer.emplace(common::provider_type_e::wevt, provider);
					output_cache_.push(path_, buffer);
				}
			}
		}

		return status == ERROR_SUCCESS;
	}

	TDHSTATUS wevt::record_at(const int& at, common::record_s& record) 
	{
		if (event_info_ == nullptr) {
			throw std::exception("wevt_metadata_c::record_at: mp_provider_info_ nullptr");
		}

		if (guid_ == nullptr) {
			throw std::exception("wevt_metadata_c::record_at: mp_provider_guid_ nullptr");
		}

		TDHSTATUS status{ (ULONG)-1 };
		auto& event_descriptor = event_info_->EventDescriptorsArray[at];

		ULONG trace_info_size{ 0 };
		TRACE_EVENT_INFO* trace_info{ nullptr };
		std::vector<BYTE> trace_info_buffer;

		do {
			if (status == ERROR_INSUFFICIENT_BUFFER) {
				try {
					trace_info_buffer.resize(trace_info_size);
					trace_info = (TRACE_EVENT_INFO*)&trace_info_buffer.at(0);
					status = ERROR_SUCCESS;
				}
				catch (std::bad_alloc) {
					status = ERROR_OUTOFMEMORY;
				}
			}

			status = ::TdhGetManifestEventInformation(
				guid_,
				(EVENT_DESCRIPTOR*)&event_descriptor,
				trace_info,
				&trace_info_size);

		} while (status == ERROR_INSUFFICIENT_BUFFER);

		if (status == ERROR_SUCCESS) {

			//ProviderName
			if (trace_info->ProviderNameOffset) {
				if (provider_name_.empty()) {
					provider_name_.assign((PCWSTR)(&trace_info_buffer.at(0) + trace_info->ProviderNameOffset));
				}
			}

			//EventName
			if (trace_info->EventNameOffset) {
				record.m_record_name = (PCWSTR)(&trace_info_buffer.at(0) + trace_info->EventNameOffset);
			}

			record.channel = event_descriptor.Channel;
			record.evel = event_descriptor.Level;
			record.opcode = event_descriptor.Opcode;
			record.keyword = event_descriptor.Keyword;
			record.version = event_descriptor.Version;
			record.id = event_descriptor.Id;

			for (ULONG count = 0; count < trace_info->TopLevelPropertyCount; count++) {
				auto& event_property = trace_info->EventPropertyInfoArray[count];
				common::record_specific_metadata_s field;

				//FieldName
				if (event_property.NameOffset) {
					field.field_name = (PCWSTR)(&trace_info_buffer.at(0) + event_property.NameOffset);
				}

				if ((event_property.Flags & PropertyStruct) == 0) {
					field.out_type = event_property.nonStructType.OutType;
					field.in_type = event_property.nonStructType.InType;
				}
				record.fields.push_back(field);
			}
		}

		return status;
	}
}
