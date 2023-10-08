from .connections import logger, post_new_tags, delete_tag


def update_tags(current_tags, new_list_of_tags, f_id):
    compared_tags_list = []

    # Condition if current finding don't have any tags. We just add new tags
    if len(current_tags) == 0:
        post_new_tags(new_list_of_tags, f_id)
        logger.info(f"Found new tags {new_list_of_tags} for finding - {f_id}")

    # Here we find some tags in finding. Checking tags of finding and new tags. Update tags witch conditions
    if len(current_tags) != 0:
        # Loop to compare tags
        for current_tag in current_tags:
            for new_tag in new_list_of_tags:
                if ("av" in current_tag and "av" in new_tag) or ("ac" in current_tag and "ac" in new_tag) or ("base" in current_tag and "base" in new_tag) or ("exploitability" in current_tag and "exploitability" in new_tag) or ("impact" in current_tag and "impact" in new_tag) or ("epss" in current_tag and "epss" in new_tag):
                    if current_tag != new_tag:
                        delete_tag(current_tag, f_id)
                        compared_tags_list.append(new_tag)
        post_new_tags(compared_tags_list, f_id)
        logger.info(f"Updated new tags - {compared_tags_list} for finding - {f_id}")

