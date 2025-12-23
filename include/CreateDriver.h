/*
	***************************************************
	*  Author: Th3Spl                                 *
	*  Lang: C++ | Usable in C as well                *
	*  Date: 27/12/2023                               *
	*  Purpose: IoCreateDriver Implementation         *
	***************************************************
*/

#pragma once

//
// Inclusions
//
#include <ntifs.h>
#include <ntstrsafe.h>
#include <windef.h>
#include "definitions.h"

extern "C" __declspec(dllimport) void* IoDriverObjectType;

extern "C" NTSTATUS __stdcall ObCreateObject(
	std::uint8_t object_type,
	void* object_type_address,
	OBJECT_ATTRIBUTES* object_attributes,
	std::uint8_t access_mode,
	void* parse_context,
	std::uint32_t object_size,
	std::uint32_t page_charge,
	std::uint32_t tag,
	void** object
);
namespace ioctl
{
	NTSTATUS create_driver(NTSTATUS(*entry_point)(DRIVER_OBJECT*, UNICODE_STRING*));
}


NTSTATUS ioctl::create_driver(NTSTATUS(*entry_point)(DRIVER_OBJECT*, UNICODE_STRING*))
{
    DRIVER_OBJECT* driver_object = nullptr;
    wchar_t name_buffer[100] = { 0 };
    UNICODE_STRING driver_name;
    OBJECT_ATTRIBUTES obj_attributes;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    auto timestamp = KeQueryUnbiasedInterruptTime();
    int pos = 0;
    name_buffer[pos++] = L'\\';
    name_buffer[pos++] = L'D';
    name_buffer[pos++] = L'r';
    name_buffer[pos++] = L'i';
    name_buffer[pos++] = L'v';
    name_buffer[pos++] = L'e';
    name_buffer[pos++] = L'r';
    name_buffer[pos++] = L'\\';

    for (int i = 0; i < 8; i++) {
        int digit = (timestamp >> (28 - i * 4)) & 0xF;
        name_buffer[pos++] = digit < 10 ? (L'0' + digit) : (L'A' + digit - 10);
    }

    auto name_length = static_cast<uint16_t>(pos);
    if (name_length == 0)
        return STATUS_INVALID_PARAMETER;

    driver_name.Length = name_length * sizeof(wchar_t);
    driver_name.MaximumLength = driver_name.Length + sizeof(wchar_t);
    driver_name.Buffer = name_buffer;

    InitializeObjectAttributes(
        &obj_attributes,
        &driver_name,
        0x00000240,
        nullptr,
        nullptr
    );

    auto obj_size = sizeof(DRIVER_OBJECT) + sizeof(void*) * 10;

    void* driver_obj_ptr = nullptr;
    status = ObCreateObject(
        0,
        IoDriverObjectType,
        &obj_attributes,
        0,
        nullptr,
        obj_size,
        0,
        0,
        &driver_obj_ptr
    );
    if (status != STATUS_SUCCESS || !driver_obj_ptr)
        return status;

    driver_object = static_cast<DRIVER_OBJECT*>(driver_obj_ptr);

    RtlZeroMemory(driver_object, obj_size);
    driver_object->Type = 4;
    driver_object->Size = sizeof(DRIVER_OBJECT);
    driver_object->Flags = 2;

    driver_object->DriverExtension = reinterpret_cast<PDRIVER_EXTENSION>(reinterpret_cast<std::uint8_t*>(driver_object) + sizeof(DRIVER_OBJECT));

    if (!driver_object->DriverExtension) {
        ObMakeTemporaryObject(driver_object);
        ObDereferenceObject(driver_object);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (int i = 0; i <= 0x1B; i++)
        driver_object->MajorFunction[i] = nullptr;

    status = entry_point(driver_object, nullptr);
    ObMakeTemporaryObject(driver_object);
    ObDereferenceObject(driver_object);
    return status;
}
