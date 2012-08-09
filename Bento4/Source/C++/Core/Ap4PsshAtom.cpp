/*****************************************************************
|
|    AP4 - pssh Atoms 
|
|    Copyright 2002-2012 Axiomatic Systems, LLC
|
|
|    This file is part of Bento4/AP4 (MP4 Atom Processing Library).
|
|    Unless you have obtained Bento4 under a difference license,
|    this version of Bento4 is Bento4|GPL.
|    Bento4|GPL is free software; you can redistribute it and/or modify
|    it under the terms of the GNU General Public License as published by
|    the Free Software Foundation; either version 2, or (at your option)
|    any later version.
|
|    Bento4|GPL is distributed in the hope that it will be useful,
|    but WITHOUT ANY WARRANTY; without even the implied warranty of
|    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
|    GNU General Public License for more details.
|
|    You should have received a copy of the GNU General Public License
|    along with Bento4|GPL; see the file COPYING.  If not, write to the
|    Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA
|    02111-1307, USA.
|
 ****************************************************************/

/*----------------------------------------------------------------------
|   includes
+---------------------------------------------------------------------*/
#include "Ap4PsshAtom.h"
#include "Ap4Utils.h"
#include "Ap4AtomFactory.h"
#include "Ap4Marlin.h"

/*----------------------------------------------------------------------
|   constants
+---------------------------------------------------------------------*/
const unsigned int AP4_PSSH_MAX_DATA_SIZE = 16*1024*1024; // 16MB, for sanity

/*----------------------------------------------------------------------
|   dynamic cast support
+---------------------------------------------------------------------*/
AP4_DEFINE_DYNAMIC_CAST_ANCHOR(AP4_PsshAtom)

/*----------------------------------------------------------------------
|   AP4_PsshAtom::Create
+---------------------------------------------------------------------*/
AP4_PsshAtom*
AP4_PsshAtom::Create(AP4_Size size, AP4_ByteStream& stream)
{
    AP4_UI32 version;
    AP4_UI32 flags;
    if (AP4_FAILED(AP4_Atom::ReadFullHeader(stream, version, flags))) return NULL;
    if (version > 1) return NULL;
    return new AP4_PsshAtom(size, version, flags, stream);
}

/*----------------------------------------------------------------------
|   AP4_PsshAtom::AP4_PsshAtom
+---------------------------------------------------------------------*/
AP4_PsshAtom::AP4_PsshAtom(const unsigned char* system_id) :
    AP4_Atom(AP4_ATOM_TYPE_PSSH, AP4_FULL_ATOM_HEADER_SIZE+16+4, 0, 0)
{
    AP4_CopyMemory(m_SystemId, system_id, 16);
}

/*----------------------------------------------------------------------
|   AP4_PsshAtom::AP4_PsshAtom
+---------------------------------------------------------------------*/
AP4_PsshAtom::AP4_PsshAtom(AP4_UI32        size, 
                           AP4_UI32        version,
                           AP4_UI32        flags,
                           AP4_ByteStream& stream) :
    AP4_Atom(AP4_ATOM_TYPE_PSSH, size, version, flags)
{
    stream.Read(m_SystemId, 16);
    AP4_UI32 data_size = 0;
    stream.ReadUI32(data_size);
    if (data_size > AP4_PSSH_MAX_DATA_SIZE) return;
    m_Data.SetDataSize(data_size);
    stream.Read(m_Data.UseData(), data_size);
    if (size > AP4_FULL_ATOM_HEADER_SIZE+16+4+data_size) {
        unsigned int padding_size = size-(AP4_FULL_ATOM_HEADER_SIZE+16+4+data_size);
        m_Padding.SetDataSize(padding_size);
        stream.Read(m_Padding.UseData(), padding_size);
    }
}

/*----------------------------------------------------------------------
|   AP4_PsshAtom::SetData
+---------------------------------------------------------------------*/
AP4_Result
AP4_PsshAtom::SetData(AP4_Atom& atom)
{
    AP4_MemoryByteStream* memstr = new AP4_MemoryByteStream(m_Data);
    if (!memstr) {
        return AP4_ERROR_OUT_OF_MEMORY;
    }
    AP4_Result result = atom.Write(*memstr);
    memstr->Release();
    SetSize32(AP4_FULL_ATOM_HEADER_SIZE+16+4 + m_Data.GetDataSize()+m_Padding.GetDataSize());
    return result;
}

/*----------------------------------------------------------------------
|   AP4_PsshAtom::SetData
+---------------------------------------------------------------------*/
AP4_Result
AP4_PsshAtom::SetData(const unsigned char* data, unsigned int data_size)
{
    m_Data.SetData(data, data_size);
    SetSize32(AP4_FULL_ATOM_HEADER_SIZE+16+4 + data_size+m_Padding.GetDataSize());
    return AP4_SUCCESS;
}

/*----------------------------------------------------------------------
|   AP4_PsshAtom::SetPadding
+---------------------------------------------------------------------*/
AP4_Result
AP4_PsshAtom::SetPadding(AP4_Byte* data, unsigned int data_size)
{
    AP4_Result result;
    result = m_Padding.SetData(data, data_size);
    AP4_CHECK(result);
    SetSize32(AP4_FULL_ATOM_HEADER_SIZE+16+4 + m_Data.GetDataSize()+m_Padding.GetDataSize());
    return AP4_SUCCESS;
}

/*----------------------------------------------------------------------
|   AP4_PsshAtom::SetSystemId
+---------------------------------------------------------------------*/
void
AP4_PsshAtom::SetSystemId(const unsigned char system_id[16])
{
    AP4_CopyMemory(m_SystemId, system_id, 16);
}

/*----------------------------------------------------------------------
|   AP4_PsshAtom::WriteFields
+---------------------------------------------------------------------*/
AP4_Result
AP4_PsshAtom::WriteFields(AP4_ByteStream& stream)
{
    AP4_Result result;
    result = stream.Write(m_SystemId, 16);
    if (AP4_FAILED(result)) return result;
    result = stream.WriteUI32(m_Data.GetDataSize());
    if (AP4_FAILED(result)) return result;
    if (m_Data.GetDataSize()) {
        result = stream.Write(m_Data.GetData(), m_Data.GetDataSize());
        if (AP4_FAILED(result)) return result;
    }
    if (m_Padding.GetDataSize()) {
        result = stream.Write(m_Padding.GetData(), m_Padding.GetDataSize());
        if (AP4_FAILED(result)) return result;
    }
    
    return AP4_SUCCESS;
}

/*----------------------------------------------------------------------
|   AP4_PsshAtom::InspectFields
+---------------------------------------------------------------------*/
AP4_Result
AP4_PsshAtom::InspectFields(AP4_AtomInspector& inspector)
{
    inspector.AddField("system_id", m_SystemId, 16);
    inspector.AddField("data_size", m_Data.GetDataSize());
    if (inspector.GetVerbosity() >= 1 &&
        AP4_CompareMemory(m_SystemId, AP4_MARLIN_PSSH_SYSTEM_ID, 16) == 0) {
        AP4_MemoryByteStream* mbs = new AP4_MemoryByteStream(m_Data);
        AP4_Atom* atom;
        AP4_AtomFactory& atom_factory = AP4_DefaultAtomFactory::Instance;
        while (atom_factory.CreateAtomFromStream(*mbs, atom) == AP4_SUCCESS) {
            AP4_Position position;
            mbs->Tell(position);
            atom->Inspect(inspector);
            mbs->Seek(position);
            delete atom;
        }
        mbs->Release();
    }
    return AP4_SUCCESS;
}
