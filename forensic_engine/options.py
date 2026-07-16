from forensic_engine.constants import PDF_IMAGE_RESOLUTION

class RunOptions:
    """Runtime configuration for a forensic engine run."""

    def __init__(
        self,
        mode:           str  = "full",
        include_images: bool = False,
        pdf_dpi:        int  = PDF_IMAGE_RESOLUTION,
        known_hashes:   set  = None,
        verbose:        bool = False,
    ) -> None:
        self.mode           = mode
        self.include_images = include_images
        self.pdf_dpi        = pdf_dpi
        self.known_hashes   = known_hashes or set()
        self.verbose        = verbose
