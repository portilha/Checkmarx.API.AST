using System;
using System.Collections.Generic;
using System.Text;

namespace Checkmarx.API.AST.Enums
{
    public enum RuleType
    {

        [System.Runtime.Serialization.EnumMember(Value = @"project.id.in")]
        Project_id_in = 0,

        [System.Runtime.Serialization.EnumMember(Value = @"project.id.starts-with")]
        Project_id_startsWith = 1,

        [System.Runtime.Serialization.EnumMember(Value = @"project.id.contains")]
        Project_id_contains = 2,

        [System.Runtime.Serialization.EnumMember(Value = @"project.id.regex")]
        Project_id_regex = 3,

        [System.Runtime.Serialization.EnumMember(Value = @"project.tag.key.exists")]
        Project_tag_key_exists = 4,

        [System.Runtime.Serialization.EnumMember(Value = @"project.tag.value.exists, project.tag.key-value.exists")]
        Project_tag_value_exists__project_tag_keyValue_exists = 5,

    }
}
