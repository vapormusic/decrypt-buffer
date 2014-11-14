/*****************************************************************
|
|    AP4 - MP4 Fragmenter
|
|    Copyright 2002-2010 Axiomatic Systems, LLC
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
#include <stdio.h>
#include <stdlib.h>

#include "Ap4.h"

/*----------------------------------------------------------------------
|   constants
+---------------------------------------------------------------------*/
#define BANNER "MP4 Fragmenter - Version 1.4\n"\
               "(Bento4 Version " AP4_VERSION_STRING ")\n"\
               "(c) 2002-2014 Axiomatic Systems, LLC"

/*----------------------------------------------------------------------
|   constants
+---------------------------------------------------------------------*/
const unsigned int AP4_FRAGMENTER_DEFAULT_FRAGMENT_DURATION   = 2000; // ms
const unsigned int AP4_FRAGMENTER_MAX_AUTO_FRAGMENT_DURATION  = 15000; 

/*----------------------------------------------------------------------
|   options
+---------------------------------------------------------------------*/
struct _Options {
    unsigned int verbosity;
    bool         debug;
} Options;

/*----------------------------------------------------------------------
|   PrintUsageAndExit
+---------------------------------------------------------------------*/
static void
PrintUsageAndExit()
{
    fprintf(stderr, 
            BANNER 
            "\n\nusage: mp4fragment [options] <input> <output>\n"
            "options are:\n"
            "  --verbosity <n> sets the verbosity (details) level to <n> (between 0 and 3)\n"
            "  --debug enable debugging information output\n"
            "  --fragment-duration <milliseconds> (default = automatic)\n"
            "  --timescale <n> (use 10000000 for Smooth Streaming compatibility)\n"
            );
    exit(1);
}

/*----------------------------------------------------------------------
|   SampleArray
+---------------------------------------------------------------------*/
class SampleArray {
public:
    SampleArray(AP4_Track* track) :
        m_Track(track) {}
    virtual ~SampleArray() {}

    virtual AP4_Cardinal GetSampleCount() {
        return m_Track->GetSampleCount();
    }
    virtual AP4_Result GetSample(AP4_Ordinal index, AP4_Sample& sample) {
        return m_Track->GetSample(index, sample);
    }
    virtual AP4_Result AddSample(AP4_Sample& /*sample*/) {
        return AP4_ERROR_NOT_SUPPORTED;
    }
    
protected:
    AP4_Track* m_Track;
};

/*----------------------------------------------------------------------
|   CachedSampleArray
+---------------------------------------------------------------------*/
class CachedSampleArray : public SampleArray {
public:
    CachedSampleArray(AP4_Track* track) :
        SampleArray(track) {}

    virtual AP4_Cardinal GetSampleCount() {
        return m_Samples.ItemCount();
    }
    virtual AP4_Result GetSample(AP4_Ordinal index, AP4_Sample& sample) {
        if (index >= m_Samples.ItemCount()) {
            return AP4_ERROR_OUT_OF_RANGE;
        } else {
            sample = m_Samples[index];
            return AP4_SUCCESS;
        }
    }
    virtual AP4_Result AddSample(AP4_Sample& sample) {
        return m_Samples.Append(sample);
    }
    
protected:
    AP4_Array<AP4_Sample> m_Samples;
};

/*----------------------------------------------------------------------
|   TrackCursor
+---------------------------------------------------------------------*/
class TrackCursor
{
public:
    TrackCursor(AP4_Track* track, SampleArray* samples);
    ~TrackCursor();
    
    AP4_Result    Init();
    AP4_Result    SetSampleIndex(AP4_Ordinal sample_index);
    
    AP4_Track*    m_Track;
    SampleArray*  m_Samples;
    AP4_Ordinal   m_SampleIndex;
    AP4_Ordinal   m_FragmentIndex;
    AP4_Sample    m_Sample;
    AP4_UI64      m_Timestamp;
    bool          m_Eos;
    AP4_UI64      m_TargetDuration;
    AP4_TfraAtom* m_Tfra;
};

/*----------------------------------------------------------------------
|   TrackCursor::TrackCursor
+---------------------------------------------------------------------*/
TrackCursor::TrackCursor(AP4_Track* track, SampleArray* samples) :
    m_Track(track),
    m_Samples(samples),
    m_SampleIndex(0),
    m_FragmentIndex(0),
    m_Timestamp(0),
    m_Eos(false),
    m_TargetDuration(0),
    m_Tfra(new AP4_TfraAtom(0))
{
}

/*----------------------------------------------------------------------
|   TrackCursor::~TrackCursor
+---------------------------------------------------------------------*/
TrackCursor::~TrackCursor()
{
    delete m_Tfra;
    delete m_Samples;
}

/*----------------------------------------------------------------------
|   TrackCursor::Init
+---------------------------------------------------------------------*/
AP4_Result
TrackCursor::Init()
{
    return m_Samples->GetSample(0, m_Sample);
}

/*----------------------------------------------------------------------
|   TrackCursor::SetSampleIndex
+---------------------------------------------------------------------*/
AP4_Result
TrackCursor::SetSampleIndex(AP4_Ordinal sample_index)
{
    m_SampleIndex = sample_index;
    
    // check if we're at the end
    if (sample_index >= m_Samples->GetSampleCount()) {
        AP4_UI64 end_dts = m_Sample.GetDts()+m_Sample.GetDuration();
        m_Sample.Reset();
        m_Sample.SetDts(end_dts);
        m_Eos = true;
    } else {
        return m_Samples->GetSample(m_SampleIndex, m_Sample);
    }
    
    return AP4_SUCCESS;
}

/*----------------------------------------------------------------------
|   Fragment
+---------------------------------------------------------------------*/
static void
Fragment(AP4_File&                input_file,
         AP4_ByteStream&          output_stream,
         AP4_Array<TrackCursor*>& cursors,
         unsigned int             fragment_duration,
         AP4_UI32                 timescale)
{
    AP4_Result result;
    
    AP4_Movie* input_movie = input_file.GetMovie();
    if (input_movie == NULL) {
        fprintf(stderr, "ERROR: no moov found in the input file\n");
        return;
    }

    // create the output file object
    AP4_Movie* output_movie = new AP4_Movie(1000);
    
    // create an mvex container
    AP4_ContainerAtom* mvex = new AP4_ContainerAtom(AP4_ATOM_TYPE_MVEX);
    AP4_MehdAtom* mehd = new AP4_MehdAtom(0); 
    mvex->AddChild(mehd);
    
    // add an output track for each track in the input file
    for (unsigned int i=0; i<cursors.ItemCount(); i++) {
        AP4_Track* track = cursors[i]->m_Track;
        
        result = cursors[i]->Init();
        if (AP4_FAILED(result)) {
            fprintf(stderr, "ERROR: failed to init sample cursor (%d), skipping track %d\n", result, track->GetId());
            return;
        }

        // create a sample table (with no samples) to hold the sample description
        AP4_SyntheticSampleTable* sample_table = new AP4_SyntheticSampleTable();
        for (unsigned int j=0; j<track->GetSampleDescriptionCount(); j++) {
            AP4_SampleDescription* sample_description = track->GetSampleDescription(j);
            sample_table->AddSampleDescription(sample_description, false);
        }
        
        // create the track
        AP4_Track* output_track = new AP4_Track(track->GetType(),
                                                sample_table,
                                                track->GetId(),
                                                timescale?timescale:1000,
                                                AP4_ConvertTime(track->GetDuration(),
                                                                input_movie->GetTimeScale(),
                                                                timescale?timescale:1000),
                                                timescale?timescale:track->GetMediaTimeScale(),
                                                0,//track->GetMediaDuration(),
                                                track->GetTrackLanguage(),
                                                track->GetWidth(),
                                                track->GetHeight());
        output_movie->AddTrack(output_track);
        
        // add a trex entry to the mvex container
        AP4_TrexAtom* trex = new AP4_TrexAtom(track->GetId(),
                                              1,
                                              0,
                                              0,
                                              0);
        mvex->AddChild(trex);
    }
    
    // select the anchor cursor and set target durations
    TrackCursor* anchor_cursor = NULL;
    for (unsigned int i=0; i<cursors.ItemCount(); i++) {
        cursors[i]->m_TargetDuration = AP4_ConvertTime(fragment_duration,
                                                       1000,
                                                       cursors[i]->m_Track->GetMediaTimeScale());
        
        // use this as the anchor track if it is the first video track
        if (anchor_cursor == NULL && cursors[i]->m_Track->GetType() == AP4_Track::TYPE_VIDEO) {
            anchor_cursor = cursors[i];
        }
    }
    if (anchor_cursor == NULL) {
        // no video track to anchor with, pick the first audio track
        for (unsigned int i=0; i<cursors.ItemCount(); i++) {
            if (cursors[i]->m_Track->GetType() == AP4_Track::TYPE_AUDIO) {
                anchor_cursor = cursors[i];
                break;
            }
        }
    }
    if (anchor_cursor == NULL) {
        // this shoudl never happen
        fprintf(stderr, "ERROR: no anchor track\n");
        return;
    }
    if (Options.debug) {
        printf("Using track ID %d as anchor\n", anchor_cursor->m_Track->GetId());
    }
    
    // update the mehd duration
    mehd->SetDuration(output_movie->GetDuration());
    
    // the mvex container to the moov container
    output_movie->GetMoovAtom()->AddChild(mvex);
    
    // write the ftyp atom
    AP4_FtypAtom* ftyp = input_file.GetFileType();
    if (ftyp) {
        ftyp->Write(output_stream);
    }
                 
    // write the moov atom
    output_movie->GetMoovAtom()->Write(output_stream);
    
    // write all the fragments
    unsigned int sequence_number = 1;
    for(;;) {
        TrackCursor* cursor = NULL;

        // pick the first track with a fragment index lower than the anchor's
        for (unsigned int i=0; i<cursors.ItemCount(); i++) {
            if (cursors[i]->m_Eos) continue;
            if (cursors[i]->m_FragmentIndex < anchor_cursor->m_FragmentIndex) {
                cursor = cursors[i];
                break;
            }
        }
        
        // check if we found a non-anchor cursor to use
        if (cursor == NULL) {
            // the anchor should be used in this round, check if we can use it
            if (anchor_cursor->m_Eos) {
                // the anchor is done, pick a new anchor
                anchor_cursor = NULL;
                for (unsigned int i=0; i<cursors.ItemCount(); i++) {
                    if (cursors[i]->m_Eos) continue;
                    if (anchor_cursor == NULL ||
                        cursors[i]->m_Track->GetType() == AP4_Track::TYPE_VIDEO ||
                        cursors[i]->m_Track->GetType() == AP4_Track::TYPE_AUDIO) {
                        anchor_cursor = cursors[i];
                        if (Options.debug) {
                            printf("+++ New anchor: Track ID %d\n", anchor_cursor->m_Track->GetId());
                        }
                    }
                }
            }
            cursor = anchor_cursor;
        }
        if (cursor == NULL) break; // all done
        
        // decide how many samples go into this fragment
        AP4_UI64 target_dts;
        if (cursor == anchor_cursor) {
            target_dts = cursor->m_Sample.GetDts()+cursor->m_TargetDuration;
        } else {
            target_dts = AP4_ConvertTime(anchor_cursor->m_Sample.GetDts(),
                                         anchor_cursor->m_Track->GetMediaTimeScale(),
                                         cursor->m_Track->GetMediaTimeScale());
            if (target_dts <= cursor->m_Sample.GetDts()) {
                // we must be at the end, past the last anchor sample, just use the target duration
                target_dts = cursor->m_Sample.GetDts()+cursor->m_TargetDuration;
            }
        }

        unsigned int end_sample_index = cursor->m_Samples->GetSampleCount();
        AP4_UI64 smallest_diff = (AP4_UI64)(0xFFFFFFFFFFFFFFFFULL);
        AP4_Sample sample;
        for (unsigned int i=cursor->m_SampleIndex; i<=cursor->m_Samples->GetSampleCount(); i++) {
            AP4_UI64 dts;
            if (i < cursor->m_Samples->GetSampleCount()) {
                result = cursor->m_Samples->GetSample(i, sample);
                if (AP4_FAILED(result)) {
                    fprintf(stderr, "ERROR: failed to get sample %d (%d)\n", i, result);
                    return;
                }
                if (!sample.IsSync()) continue; // only look for sync samples
                dts = sample.GetDts();
            } else {
                result = cursor->m_Samples->GetSample(i-1, sample);
                if (AP4_FAILED(result)) {
                    fprintf(stderr, "ERROR: failed to get sample %d (%d)\n", i-1, result);
                    return;
                }
                dts = sample.GetDts()+sample.GetDuration();
            }
            AP4_SI64 diff = dts-target_dts;
            AP4_UI64 abs_diff = diff<0?-diff:diff;
            if (abs_diff < smallest_diff) {
                // this sample is the closest to the target so far
                end_sample_index = i;
                smallest_diff = abs_diff;
                if (diff >= 0) {
                    // this sample is past the target, it is not going to get any better, stop looking
                    break;
                }
            }
        }
        if (cursor->m_Eos) continue;
        
        if (Options.debug) {
            if (cursor == anchor_cursor) {
                printf("====");
            } else {
                printf("----");
            }
            printf(" Track ID %d - dts = %lld, target = %lld, pos = %d, end = %d/%d\n",
                   cursor->m_Track->GetId(),
                   cursor->m_Sample.GetDts(),
                   target_dts,
                   cursor->m_SampleIndex,
                   end_sample_index,
                   cursor->m_Track->GetSampleCount());
        }
        
        // emit a fragment for the selected track
        if (Options.verbosity > 0) {
            printf("fragment: track ID %d ", cursor->m_Track->GetId());
        }

        // remember the time and position of this fragment
        AP4_Position moof_offset = 0;
        output_stream.Tell(moof_offset);
        cursor->m_Tfra->AddEntry(cursor->m_Timestamp, moof_offset);
        
        // decide which sample description index to use
        // (this is not very sophisticated, we only look at the sample description
        // index of the first sample in the group, which may not be correct. This
        // should be fixed later)
        unsigned int sample_desc_index = cursor->m_Sample.GetDescriptionIndex();
        unsigned int tfhd_flags = AP4_TFHD_FLAG_DEFAULT_BASE_IS_MOOF;
        if (sample_desc_index > 0) {
            tfhd_flags |= AP4_TFHD_FLAG_SAMPLE_DESCRIPTION_INDEX_PRESENT;
        }
        if (cursor->m_Track->GetType() == AP4_Track::TYPE_VIDEO) {
            tfhd_flags |= AP4_TFHD_FLAG_DEFAULT_SAMPLE_FLAGS_PRESENT;
        }
            
        // setup the moof structure
        AP4_ContainerAtom* moof = new AP4_ContainerAtom(AP4_ATOM_TYPE_MOOF);
        AP4_MfhdAtom* mfhd = new AP4_MfhdAtom(sequence_number++);
        moof->AddChild(mfhd);
        AP4_ContainerAtom* traf = new AP4_ContainerAtom(AP4_ATOM_TYPE_TRAF);
        AP4_TfhdAtom* tfhd = new AP4_TfhdAtom(tfhd_flags,
                                              cursor->m_Track->GetId(),
                                              0,
                                              sample_desc_index+1,
                                              0,
                                              0,
                                              0);
        if (tfhd_flags & AP4_TFHD_FLAG_DEFAULT_SAMPLE_FLAGS_PRESENT) {
            tfhd->SetDefaultSampleFlags(0x1010000); // sample_is_non_sync_sample=1, sample_depends_on=1 (not I frame)
        }
        
        traf->AddChild(tfhd);
        AP4_TfdtAtom* tfdt = new AP4_TfdtAtom(1, cursor->m_Timestamp);
        traf->AddChild(tfdt);
        AP4_UI32 trun_flags = AP4_TRUN_FLAG_DATA_OFFSET_PRESENT     |
                              AP4_TRUN_FLAG_SAMPLE_DURATION_PRESENT |
                              AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT;
        AP4_UI32 first_sample_flags = 0;
        if (cursor->m_Track->GetType() == AP4_Track::TYPE_VIDEO) {
            trun_flags |= AP4_TRUN_FLAG_FIRST_SAMPLE_FLAGS_PRESENT;
            first_sample_flags = 0x2000000; // sample_depends_on=2 (I frame)
        }
        AP4_TrunAtom* trun = new AP4_TrunAtom(trun_flags, 0, first_sample_flags);
        
        traf->AddChild(trun);
        moof->AddChild(traf);
        
        // add samples to the fragment
        AP4_Array<AP4_UI32>            sample_indexes;
        unsigned int                   sample_count = 0;
        AP4_Array<AP4_TrunAtom::Entry> trun_entries;
        AP4_UI32                       mdat_size = AP4_ATOM_HEADER_SIZE;
        for (;;) {
            // if we have one non-zero CTS delta, we'll need to express it
            if (cursor->m_Sample.GetCtsDelta()) {
                trun->SetFlags(trun->GetFlags() | AP4_TRUN_FLAG_SAMPLE_COMPOSITION_TIME_OFFSET_PRESENT);
            }
            
            // add one sample
            trun_entries.SetItemCount(sample_count+1);
            AP4_TrunAtom::Entry& trun_entry = trun_entries[sample_count];
            trun_entry.sample_duration                = timescale?
                                                        (AP4_UI32)AP4_ConvertTime(cursor->m_Sample.GetDuration(),
                                                                                  cursor->m_Track->GetMediaTimeScale(),
                                                                                  timescale):
                                                        cursor->m_Sample.GetDuration();
            trun_entry.sample_size                    = cursor->m_Sample.GetSize();
            trun_entry.sample_composition_time_offset = timescale?
                                                        (AP4_UI32)AP4_ConvertTime(cursor->m_Sample.GetCtsDelta(),
                                                                                  cursor->m_Track->GetMediaTimeScale(),
                                                                                  timescale):
                                                        cursor->m_Sample.GetCtsDelta();
                        
            sample_indexes.SetItemCount(sample_count+1);
            sample_indexes[sample_count] = cursor->m_SampleIndex;
            mdat_size += trun_entry.sample_size;
            
            // next sample
            cursor->m_Timestamp += trun_entry.sample_duration;
            result = cursor->SetSampleIndex(cursor->m_SampleIndex+1);
            if (AP4_FAILED(result)) {
                fprintf(stderr, "ERROR: failed to get sample %d (%d)\n", cursor->m_SampleIndex+1, result);
                return;
            }
            sample_count++;
            if (cursor->m_Eos) {
                if (Options.debug) {
                    printf("[has reached the end]");
                }
                break;
            }
            if (cursor->m_SampleIndex >= end_sample_index) {
                break; // done with this fragment
            }
        }
        if (Options.verbosity) {
            printf(" %d samples\n", sample_count);
        }
                
        // update moof and children
        trun->SetEntries(trun_entries);
        trun->SetDataOffset((AP4_UI32)moof->GetSize()+AP4_ATOM_HEADER_SIZE);
        
        // write moof
        moof->Write(output_stream);
        
        // write mdat
        output_stream.WriteUI32(mdat_size);
        output_stream.WriteUI32(AP4_ATOM_TYPE_MDAT);
        AP4_DataBuffer sample_data;
        for (unsigned int i=0; i<sample_indexes.ItemCount(); i++) {
            // get the sample
            result = cursor->m_Samples->GetSample(sample_indexes[i], sample);
            if (AP4_FAILED(result)) {
                fprintf(stderr, "ERROR: failed to get sample %d (%d)\n", sample_indexes[i], result);
                return;
            }

            // read the sample data
            result = sample.ReadData(sample_data);
            if (AP4_FAILED(result)) {
                fprintf(stderr, "ERROR: failed to read sample data for sample %d (%d)\n", sample_indexes[i], result);
                return;
            }
            
            // write the sample data
            result = output_stream.Write(sample_data.GetData(), sample_data.GetDataSize());
            if (AP4_FAILED(result)) {
                fprintf(stderr, "ERROR: failed to write sample data (%d)\n", result);
                return;
            }
        }
        
        // advance the cursor's fragment index
        ++cursor->m_FragmentIndex;
        
        // cleanup
        delete moof;
    }
    
    // create an mfra container and write out the index
    AP4_ContainerAtom mfra(AP4_ATOM_TYPE_MFRA);
    for (unsigned int i=0; i<cursors.ItemCount(); i++) {
        mfra.AddChild(cursors[i]->m_Tfra);
        cursors[i]->m_Tfra = NULL;
    }
    AP4_MfroAtom* mfro = new AP4_MfroAtom((AP4_UI32)mfra.GetSize()+16);
    mfra.AddChild(mfro);
    result = mfra.Write(output_stream);
    if (AP4_FAILED(result)) {
        fprintf(stderr, "ERROR: failed to write 'mfra' (%d)\n", result);
        return;
    }
    
    // cleanup
    for (unsigned int i=0; i<cursors.ItemCount(); i++) {
        delete cursors[i];
    }
    delete output_movie;
}

/*----------------------------------------------------------------------
|   AutoDetectFragmentDuration
+---------------------------------------------------------------------*/
static unsigned int 
AutoDetectFragmentDuration(TrackCursor* cursor)
{
    AP4_Sample   sample;
    unsigned int sample_count = cursor->m_Samples->GetSampleCount();
    
    // get the first sample as the starting point
    AP4_Result result = cursor->m_Samples->GetSample(0, sample);
    if (AP4_FAILED(result)) {
        fprintf(stderr, "ERROR: failed to read first sample\n");
        return 0;
    }
    if (!sample.IsSync()) {
        fprintf(stderr, "ERROR: first sample is not an I frame\n");
        return 0;
    }
    
    for (unsigned int interval = 1; interval < sample_count; interval++) {
        bool irregular = false;
        unsigned int sync_count = 0;
        unsigned int i;
        for (i = 0; i < sample_count; i += interval) {
            result = cursor->m_Samples->GetSample(i, sample);
            if (AP4_FAILED(result)) {
                fprintf(stderr, "ERROR: failed to read sample %d\n", i);
                return 0;
            }
            if (!sample.IsSync()) {
                irregular = true;
                break;
            }
            ++sync_count;
        }
        if (sync_count < 1) continue;
        if (!irregular) {
            // found a pattern
            AP4_UI64 duration = sample.GetDts();
            double fps = (double)(interval*(sync_count-1))/((double)duration/(double)cursor->m_Track->GetMediaTimeScale());
            if (Options.verbosity > 0) {
                printf("found regular I-frame interval: %d frames (at %.3f frames per second)\n",
                       interval, (float)fps);
            }
            return (unsigned int)(1000.0*(double)interval/fps);
        }
    }
    
    return 0;
}

/*----------------------------------------------------------------------
|   main
+---------------------------------------------------------------------*/
int
main(int argc, char** argv)
{
    if (argc < 2) {
        PrintUsageAndExit();
    }

    // init the variables
    const char*  input_filename                = NULL;
    const char*  output_filename               = NULL;
    unsigned int fragment_duration             = 0;
    bool         auto_detect_fragment_duration = true;
    AP4_UI32     timescale = 0;
    AP4_Result   result;

    Options.verbosity = 0;
    Options.debug     = false;
    
    // parse the command line
    argv++;
    char* arg;
    while ((arg = *argv++)) {
        if (!strcmp(arg, "--verbosity")) {
            arg = *argv++;
            if (arg == NULL) {
                fprintf(stderr, "ERROR: missing argument after --verbosity option\n");
                return 1;
            }
            Options.verbosity = strtoul(arg, NULL, 10);
        } else if (!strcmp(arg, "--debug")) {
            Options.debug = true;
        } else if (!strcmp(arg, "--fragment-duration")) {
            arg = *argv++;
            if (arg == NULL) {
                fprintf(stderr, "ERROR: missing argument after --fragment-duration option\n");
                return 1;
            }
            fragment_duration = strtoul(arg, NULL, 10);
            auto_detect_fragment_duration = false;
        } else if (!strcmp(arg, "--timescale")) {
            arg = *argv++;
            if (arg == NULL) {
                fprintf(stderr, "ERROR: missing argument after --timescale option\n");
                return 1;
            }
            timescale = strtoul(arg, NULL, 10);
        } else {
            if (input_filename == NULL) {
                input_filename = arg;
            } else if (output_filename == NULL) {
                output_filename = arg;
            } else {
                fprintf(stderr, "ERROR: unexpected argument '%s'\n", arg);
                return 1;
            }
        }
    }
    if (Options.debug && Options.verbosity == 0) {
        Options.verbosity = 1;
    }
    
    if (input_filename == NULL) {
        fprintf(stderr, "ERROR: no input specified\n");
        return 1;
    }
    AP4_ByteStream* input_stream = NULL;
    result = AP4_FileByteStream::Create(input_filename, 
                                        AP4_FileByteStream::STREAM_MODE_READ, 
                                        input_stream);
    if (AP4_FAILED(result)) {
        fprintf(stderr, "ERROR: cannot open input (%d)\n", result);
        return 1;
    }
    if (output_filename == NULL) {
        fprintf(stderr, "ERROR: no output specified\n");
        return 1;
    }
    AP4_ByteStream* output_stream = NULL;
    result = AP4_FileByteStream::Create(output_filename, 
                                        AP4_FileByteStream::STREAM_MODE_WRITE,
                                        output_stream);
    if (AP4_FAILED(result)) {
        fprintf(stderr, "ERROR: cannot create/open output (%d)\n", result);
        return 1;
    }
    
    // parse the input MP4 file (moov only)
    AP4_File input_file(*input_stream, AP4_DefaultAtomFactory::Instance, true);
    
    // check the file for basic properties
    if (input_file.GetMovie() == NULL) {
        fprintf(stderr, "ERROR: no movie found in the file\n");
        return 1;
    }
    if (input_file.GetMovie()->HasFragments()) {
        fprintf(stderr, "NOTICE: file is already fragmented, it will be re-fragmented\n");
    }

    // create a cusor list to keep track of the tracks we will read from
    AP4_Array<TrackCursor*> cursors;
    
    // iterate over all tracks
    TrackCursor*  video_track = NULL;
    unsigned int video_track_count = 0;
    unsigned int audio_track_count = 0;
    for (AP4_List<AP4_Track>::Item* track_item = input_file.GetMovie()->GetTracks().FirstItem();
                                    track_item;
                                    track_item = track_item->GetNext()) {
        AP4_Track* track = track_item->GetData();

        if (track->GetSampleCount() == 0 && !input_file.GetMovie()->HasFragments()) {
            fprintf(stderr, "WARNING: track %d has no samples, it will be skipped\n", track->GetId());
            continue;
        }

        // create a sample array for this track
        SampleArray* sample_array;
        if (input_file.GetMovie()->HasFragments()) {
            sample_array = new CachedSampleArray(track);
        } else {
            sample_array = new SampleArray(track);
        }

        // create a cursor for the track
        TrackCursor* cursor = new TrackCursor(track, sample_array);
        cursor->m_Tfra->SetTrackId(track->GetId());
        cursors.Append(cursor);

        if (track->GetType() == AP4_Track::TYPE_VIDEO) {
            if (video_track) {
                fprintf(stderr, "WARNING: more than one video track found\n");
            } else {
                video_track = cursor;
            }
            video_track_count++;
        } else if (track->GetType() == AP4_Track::TYPE_AUDIO) {
            audio_track_count++;
        }
    }

    if (cursors.ItemCount() == 0) {
        fprintf(stderr, "ERROR: no valid track found\n");
        return 1;
    }
    
    if (video_track_count == 0 && audio_track_count == 0) {
        fprintf(stderr, "ERROR: no audio or video track in the file\n");
        return 1;
    }
    
    // for fragmented input files, we need to populate the sample arrays
    if (input_file.GetMovie()->HasFragments()) {
        // remember where the stream was
        AP4_Position position;
        input_stream->Tell(position);
        
        AP4_LinearReader reader(*input_file.GetMovie(), input_stream);
        for (unsigned int i=0; i<cursors.ItemCount(); i++) {
            reader.EnableTrack(cursors[i]->m_Track->GetId());
        }
        AP4_UI32 track_id;
        AP4_Sample sample;
        do {
            result = reader.GetNextSample(sample, track_id);
            if (AP4_SUCCEEDED(result)) {
                for (unsigned int i=0; i<cursors.ItemCount(); i++) {
                    if (cursors[i]->m_Track->GetId() == track_id) {
                        cursors[i]->m_Samples->AddSample(sample);
                        break;
                    }
                }
            }
        } while (AP4_SUCCEEDED(result));
        
        // return the stream to its original position
        input_stream->Seek(position);
    }

    // auto-detect the fragment duration if needed
    if (auto_detect_fragment_duration) {
        if (video_track) {
            fragment_duration = AutoDetectFragmentDuration(video_track);
        } else {
            if (Options.verbosity > 0) {
                fprintf(stderr, "no video track, cannot autodetect fragment duration\n");
            }
        }
        if (fragment_duration == 0) {
            if (Options.verbosity > 0) {
                fprintf(stderr, "unable to detect fragment duration, using default\n");
            }
            fragment_duration = AP4_FRAGMENTER_DEFAULT_FRAGMENT_DURATION;
        } else if (fragment_duration > AP4_FRAGMENTER_MAX_AUTO_FRAGMENT_DURATION) {
            if (Options.verbosity > 0) {
                fprintf(stderr, "auto-detected fragment duration too large, using default\n");
            }
            fragment_duration = AP4_FRAGMENTER_DEFAULT_FRAGMENT_DURATION;
        }
    }
    
    // fragment the file
    Fragment(input_file, *output_stream, cursors, fragment_duration, timescale);
    
    // cleanup and exit
    if (input_stream)  input_stream->Release();
    if (output_stream) output_stream->Release();

    return 0;
}
