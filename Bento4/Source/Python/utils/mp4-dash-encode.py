from optparse import OptionParser
from mp4utils import *
from subprocess import check_output, CalledProcessError
import json
import math

# setup main options
VERSION = "1.0.0"
SVN_REVISION = "$Revision: 539 $"
SCRIPT_PATH = path.abspath(path.dirname(__file__))
sys.path += [SCRIPT_PATH]
TempFiles = []

def scale_resolution(pixels, aspect_ratio):
    x = 16*((int(math.ceil(math.sqrt(pixels*aspect_ratio)))+15)/16)
    y = 16*((int(math.ceil(x/aspect_ratio))+15)/16)
    return (x,y)

def compute_bitrates_and_resolutions(options):
    # spread the bitrates evenly
    if options.bitrates > 1:
        delta = (options.max_bitrate-options.min_bitrate)/(options.bitrates-1)
    else:
        delta = 0
    bitrates = [options.min_bitrate+delta*i for i in range(options.bitrates)]
    max_pixels = options.resolution[0]*options.resolution[1]
    pixels = [max_pixels*pow(bitrate/options.max_bitrate, 4.0/3.0) for bitrate in bitrates]
    resolutions = [scale_resolution(x, float(options.resolution[0])/float(options.resolution[1])) for x in pixels]
    bits_per_pixel = [1000.0*bitrates[i]/(24*pixels[i]) for i in range(len(pixels))]

    if options.debug:
        print 'BITRATES:', bitrates
        print 'PIXELS: ', pixels
        print 'RESOLUTIONS: ', resolutions
        print 'BITS PER PIXEL:', bits_per_pixel

    return (bitrates, resolutions)

def run_command(options, cmd):
    if options.debug:
        print 'COMMAND: ', cmd
    try:
        return check_output(cmd, shell=True)
    except CalledProcessError, e:
        message = "binary tool failed with error %d" % e.returncode
        if options.verbose:
            message += " - " + str(cmd)
        raise Exception(message)

class MediaSource:
    def __init__(self, options, filename):
        self.width = 0
        self.height = 0
        self.frame_rate = 0

        if not options.debug:
            quiet = '-v quiet '
        else:
            quiet = ''

        command = 'ffprobe -of json -show_format -show_streams '+quiet+filename
        json_probe = run_command(options, command)
        self.json_info = json.loads(json_probe, strict=False)

        for stream in self.json_info['streams']:
            if stream['codec_type'] == 'video':
                self.width = stream['width']
                self.height = stream['height']
                if '/' in stream['avg_frame_rate']:
                    (x,y) = stream['avg_frame_rate'].split('/')
                    self.frame_rate = float(x)/float(y)
                else:
                    self.frame_rate = float(stream['avg_frame_rate'])

    def __repr__(self):
        return 'Video: resolution='+str(self.width)+'x'+str(self.height)

def main():
    # parse options
    global Options
    parser = OptionParser(usage="%prog [options] <media-file>",
                          description="<media-file> is the path to a source video file. Version " + VERSION + " r" + SVN_REVISION[-5:-2])
    parser.add_option('-v', '--verbose', dest="verbose", action='store_true', default=False,
                      help="Be verbose")
    parser.add_option('-d', '--debug', dest="debug", action='store_true', default=False,
                      help="Print out debugging information")
    parser.add_option('-o', '--output-dir', dest="output_dir",
                      help="Output directory", metavar="<output-dir>", default='output')
    parser.add_option('-b', '--bitrates', dest="bitrates",
                      help="Number of bitrates (default: 1)", default=1, type='int')
    parser.add_option('-r', '--resolution', dest='resolution',
                      help="Resolution of the source video (default: auto detect)")
    parser.add_option('-m', '--min-video-bitrate', dest='min_bitrate', type='float',
                      help="Minimum bitrate (default: 500kbps)", default=500.0)
    parser.add_option('-n', '--max-video-bitrate', dest='max_bitrate', type='float',
                      help="Max Video bitrate (default: 2mbps)", default=2000.0)
    parser.add_option('-a', '--audio-bitrate', dest='audio_bitrate', type='int',
                      help="Audio bitrate (default: 128kbps)", default=128)
    parser.add_option('-s', '--segment-size', dest='segment_size', type='int',
                      help="Video segment size in frames (default: 3*fps)")
    parser.add_option('-f', '--force', dest="force_output", action="store_true",
                      help="Overwrite output files if they already exist", default=False)
    (options, args) = parser.parse_args()
    Options = options
    if len(args) == 0:
        parser.print_help()
        sys.exit(1)

    if options.resolution:
        options.resolution = [int(x) for x in options.resolution.split('x')]
        if len(options.resolution) != 2:
            raise Exception('ERROR: invalid value for --resolution argument')

    if options.min_bitrate > options.max_bitrate:
        raise Exception('ERROR: max bitrate must be >= min bitrate')

    if options.verbose:
        print 'Encoding', options.bitrates, 'bitrates, min bitrate =', options.min_bitrate, 'max bitrate =', options.max_bitrate

    media_source = MediaSource(options, args[0])
    if not options.resolution:
        options.resolution = [media_source.width, media_source.height]
    if options.verbose:
        print 'Media Source:', media_source

    if not options.segment_size:
        options.segment_size = 3*int(media_source.frame_rate+0.5)

    if options.bitrates == 1:
        options.min_bitrate = options.max_bitrate

    (bitrates, resolutions) = compute_bitrates_and_resolutions(options)

    for i in range(options.bitrates):
        output_filename = 'video_%05d.mp4' % int(bitrates[i])
        temp_filename = output_filename+'_'
        base_cmd  = "ffmpeg -i %s -strict experimental -acodec libfdk_aac -ac 2 -ab %dk -profile:v baseline -preset slow -vcodec libx264" % (args[0], options.audio_bitrate)
        if not options.debug:
            base_cmd += ' -v quiet'
        if options.force_output:
            base_cmd += ' -y'
        x264_opts = "-x264opts keyint=%d:min-keyint=%d:scenecut=0:rc-lookahead=%d" % (options.segment_size, options.segment_size, options.segment_size)
        x264_opts += ':vbv-bufsize=%d:vbv-maxrate=%d' % (bitrates[i], int(bitrates[i]*1.5))
        cmd = base_cmd+' '+x264_opts+' -s '+str(resolutions[i][0])+'x'+str(resolutions[i][1])+' -f mp4 '+temp_filename
        if options.verbose:
            print 'ENCODING bitrate', int(bitrates[i])
        run_command(options, cmd)

        cmd = 'mp4fragment %s %s' % (temp_filename, output_filename)
        run_command(options, cmd)

        os.unlink(temp_filename)

###########################
if __name__ == '__main__':
    global Options
    Options = None
    try:
        main()
    except Exception, err:
        if Options is None or Options.debug:
            raise
        else:
            PrintErrorAndExit('ERROR: %s\n' % str(err))
    finally:
        for f in TempFiles:
            os.unlink(f)
