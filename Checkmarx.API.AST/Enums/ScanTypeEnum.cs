﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace Checkmarx.API.AST.Enums
{
    public enum ScanTypeEnum
    {
        [Description("sast")]
        sast,

        [Description("kics")]
        kics,

        [Description("sca")]
        sca,
    }
}
