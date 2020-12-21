# encoding: utf-8

from optparse import OptionParser


class MyParser(OptionParser):
    # 打印用法描述，即描述该脚本的用途(在Usage和Option之间展示)
    def format_description(self, formatter):
        if self.description:
            return self.description
        else:
            return ""

    # 打印举例信息(在Option之后展示)
    def format_epilog(self, formatter):
        if self.epilog:
            return "\n" + self.epilog
        else:
            return ""


if __name__ == '__main__':
    help_info = 'Usage: ...'
    parser = MyParser(epilog=help_info, description="123")
    parser.add_option(
        '--modle',
        action='store',
        dest='modle',
        default=False,
        type='string',
        help="add_zone|delete_zone|upload|add_table|modify_table|clear_table|delete_table"
    )
    parser.add_option(
        '--filepath',
        action='store',
        dest='filepath',
        type='string',
        default=False,
        help='path for xml/tdr file.'
    )

    (options, args) = parser.parse_args()
    if not options.modle:
        parser.error('option --modle not supplied')
    if not options.filepath:
        parser.error('option --filepath not supplied')
    print(options)
    print(options.modle, options.filepath)
