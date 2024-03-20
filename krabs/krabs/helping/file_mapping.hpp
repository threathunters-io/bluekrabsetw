#pragma once
#include <string>

// Exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEAN             
#include <windows.h>

namespace krabs {
	class file_mapping {

	public:
		file_mapping() {};
		file_mapping(const std::wstring& path);
		~file_mapping();

		void create_mapping(const std::wstring& path);
		BYTE* get_base_addr();
		LARGE_INTEGER get_size();
	protected:

	private:
		std::wstring path_;
		HANDLE file_handle_{ INVALID_HANDLE_VALUE };
		HANDLE mem_map_handle_{ INVALID_HANDLE_VALUE };
		BYTE* mem_map_base_addr_{ nullptr };
		LARGE_INTEGER size_{ 0 };
	};


	// Implementation
	// ------------------------------------------------------------------------

	file_mapping::file_mapping(const std::wstring& path)
		: path_(path)
	{
		if (path_.empty())
			throw std::exception("file_mapping::file_mapping: path_ empty");

		file_handle_ = ::CreateFile(m_path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
		if (file_handle_ == INVALID_HANDLE_VALUE)
			throw std::exception("file_mapping::file_mapping: file_handle_ INVALID_HANDLE_VALUE");

		/*
		* If this parameterand dwMaximumSizeHigh are 0 (zero),
		* the maximum size of the file mapping object is equal
		* to the current size of the file that hFile identifies.
		*/
		mem_map_handle_ = ::CreateFileMapping(file_handle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
		if (mem_map_handle_ == INVALID_HANDLE_VALUE)
			throw std::exception("file_mapping::file_mapping: mem_map_handle_ INVALID_HANDLE_VALUE");
	}

	file_mapping::~file_mapping()
	{
		if (mem_map_handle_ != INVALID_HANDLE_VALUE)
		{
			::UnmapViewOfFile(mem_map_base_addr_);
			::CloseHandle(mem_map_handle_);
		}

		if (file_handle_ != INVALID_HANDLE_VALUE)
			::CloseHandle(m_file_handle_);
	}

	void file_mapping::create_mapping(const std::wstring& path)
	{
		bool status = false;

		file_handle_ = ::CreateFile(m_path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
		if (file_handle_ != INVALID_HANDLE_VALUE) {
			/*
			* If this parameterand dwMaximumSizeHigh are 0 (zero),
			* the maximum size of the file mapping object is equal
			* to the current size of the file that hFile identifies.
			*/
			mem_map_handle_ = ::CreateFileMapping(m_file_handle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
			if (mem_map_handle_ != NULL) {
				/*
				* If the object exists before the function call, 
				* the function returns a handle to the existing
				* object (with its current size, not the specified size),
				* and GetLastError returns ERROR_ALREADY_EXISTS.
				*/
				status = true;
			}
		}
		
		return status;
	}

	BYTE* file_mapping::get_base_addr()
	{
		if (mem_map_handle_ == INVALID_HANDLE_VALUE)
			throw std::exception("file_mapping::get_base_addr: mem_map_handle_ INVALID_HANDLE_VALUE");

		if (!mem_map_base_addr_)
			mem_map_base_addr_ = (PBYTE)::MapViewOfFile(mem_map_handle_, FILE_MAP_READ, 0, 0, 0);

		return mem_map_base_addr_;

	}

	LARGE_INTEGER file_mapping::get_size()
	{
		if (file_handle_ == INVALID_HANDLE_VALUE)
			throw std::exception("file_mapping::get_size: file_handle_ INVALID_HANDLE_VALUE");

		if (!size_.QuadPart)
			::GetFileSizeEx(file_handle_, &size_);

		return size_;
	}
}