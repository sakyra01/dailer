from .connections import logger, post_new_tags, delete_tag


def update_tags(current_tags, new_list_of_tags, f_id):
    compared_tags_list = []

    # Condition if current finding don't have any tags. We just add new tags
    if len(current_tags) == 0:
        post_new_tags(new_list_of_tags, f_id)
        logger.info(f"Add new tags {new_list_of_tags} for finding - {f_id}")

    # Here we find some tags in finding. Checking tags of finding and new tags. Update tags witch conditions
    if len(current_tags) != 0:
        # Loop to compare tags
        for current_tag in current_tags:
            for new_tag in new_list_of_tags:
                if ("av_" in current_tag and "av_" in new_tag) or ("ac_" in current_tag and "ac_" in new_tag) or ("base_" in current_tag and "base_" in new_tag) or ("exploitability_" in current_tag and "exploitability_" in new_tag) or ("impact_" in current_tag and "impact_" in new_tag) or ("epss_" in current_tag and "epss_" in new_tag):
                    if current_tag != new_tag:
                        delete_tag(current_tag, f_id)
                        compared_tags_list.append(new_tag)

        if len(compared_tags_list) != 0:
            post_new_tags(compared_tags_list, f_id)
            logger.info(f"Updated tags for old tags - {compared_tags_list} for finding - {f_id}")
        else:
            logger.info(f"New tags are the same as old tags for finding. No need to update finding - {f_id}")
