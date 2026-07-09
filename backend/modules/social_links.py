from .base import BaseModule, ModuleResult, ModuleStatus


class SocialLinksModule(BaseModule):
    name = "social_links"
    description = "Discover social media profiles plausibly linked to the email address."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        username = email.split("@")[0]
        
        variations = set()
        variations.add(username)
        variations.add(username.replace(".", ""))
        variations.add(username.replace(".", "_"))
        
        if "." in username:
            parts = username.split(".")
            if len(parts) >= 2:
                variations.add(parts[0][0] + parts[1]) # e.g. kmoses
                variations.add(parts[0]) # e.g. katriel

        variations_list = list(variations)
        
        findings = [
            {"platform": "social_links", "metadata": {"common_variations": variations_list}, "confidence": "low"}
        ]
        
        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            metadata={"derived_username": username, "common_variations": variations_list},
            findings=findings
        )
