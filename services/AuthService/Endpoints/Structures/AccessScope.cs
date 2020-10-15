/// MIT License, Copyright Burak Kara, burak@burak.io, https://en.wikipedia.org/wiki/MIT_License

using System.Collections.Generic;
using System.Text.RegularExpressions;
using BCommonUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthService.Endpoints.Structures
{
    public class AccessScopeLibrary
    {
        public static readonly List<string> ACCESS_RIGHTS = new List<string>
        {
            "GET", "POST", "PUT", "DELETE"
        };

        public static string GetPossibleAccessRightsText()
        {
            var Result = "";
            foreach (var Right in ACCESS_RIGHTS)
            {
                Result += Right + ", ";
            }
            Result = Result.TrimEnd(' ').TrimEnd(',');
            return Result;
        }

        public static bool CheckBaseFinalFullContainment(List<AccessScope> _BaseScopeList, List<AccessScope> _FinalScopeList)
        {
            foreach (var FinalScope in _FinalScopeList)
            {
                bool bFound = false;

                foreach (var BaseScope in _BaseScopeList)
                {
                    //Checked
                    if (Regex.IsMatch(FinalScope.WildcardPath, BUtility.WildCardToRegular(BaseScope.WildcardPath)))
                    {
                        bool bAccessRightsExist = true;

                        foreach (var FinalAccessRight in FinalScope.AccessRights)
                        {
                            if (!BaseScope.AccessRights.Contains(FinalAccessRight))
                            {
                                bAccessRightsExist = false;
                                break;
                            }
                        }

                        if (bAccessRightsExist)
                        {
                            bFound = true;
                            break;
                        }
                    }
                }

                if (!bFound)
                {
                    return false;
                }
            }
            return true;
        }

        public static void CombineRightsOfAccessScopeLists_IntoNew(List<AccessScope> _NewFinalScopeList, List<AccessScope> _ExistingFinalScopeList)
        {
            foreach (var ExistingScope in _ExistingFinalScopeList)
            {
                bool bFound = false;

                foreach (var NewScope in _NewFinalScopeList)
                {
                    if (NewScope.WildcardPath == ExistingScope.WildcardPath)
                    {
                        bFound = true;

                        foreach (var ExistingRight in ExistingScope.AccessRights)
                        {
                            if (!NewScope.AccessRights.Contains(ExistingRight))
                            {
                                NewScope.AccessRights.Add(ExistingRight);
                            }
                        }
                        break;
                    }
                }
                if (!bFound)
                {
                    _NewFinalScopeList.Add(ExistingScope);
                }
            }
        }
        public static void UnionMergeRights(JArray _MergeInto, JArray _Source)
        {
            foreach (var CurrentSourceToken in _Source)
            {
                UnionMergeRightsInternal(_MergeInto, (JObject)CurrentSourceToken);
            }
        }
        private static void UnionMergeRightsInternal(JArray _MergeInto, JObject _SourceJObject)
        {
            var SourceWildcardPath = (string)_SourceJObject[AccessScope.WILDCARD_PATH_PROPERTY];
            var SourceAccessRights = (JArray)_SourceJObject[AccessScope.ACCESS_RIGHTS_PROPERTY];

            if (SourceAccessRights.Count == 0) return;

            foreach (var CurrentDestinationToken in _MergeInto)
            {
                var DestinationJObject = (JObject)CurrentDestinationToken;
                var DestinationWildcardPath = (string)DestinationJObject[AccessScope.WILDCARD_PATH_PROPERTY];
                if (DestinationWildcardPath == SourceWildcardPath)
                {
                    var DestinationAccessRightsJArray = (JArray)DestinationJObject[AccessScope.ACCESS_RIGHTS_PROPERTY];
                    DestinationAccessRightsJArray.Merge(SourceAccessRights, new JsonMergeSettings()
                    {
                        MergeArrayHandling = MergeArrayHandling.Union
                    });
                    return;
                }
            }

            _MergeInto.Add(_SourceJObject);
        }
    }

    public class AccessScope
    {
        public const string WILDCARD_PATH_PROPERTY = "wildcardPath";
        public const string ACCESS_RIGHTS_PROPERTY = "accessRights";

        [JsonProperty(WILDCARD_PATH_PROPERTY)]
        public string WildcardPath;

        [JsonProperty(ACCESS_RIGHTS_PROPERTY)]
        public List<string> AccessRights = new List<string>();
    }
}