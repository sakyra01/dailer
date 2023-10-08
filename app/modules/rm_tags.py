from .connections import delete_tag


def rm_tags(f_tags, f_id):

    # Loop checker for vpr_tag and tenable-db tag
    if len(f_tags) != 0:
        for tag in f_tags:
            if 'vpr' in tag or 'tenable' in tag:
                delete_tag(tag, f_id)
