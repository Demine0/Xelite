using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Xelite.Core;

namespace Xelite
{
    public abstract class Observable : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        protected void Set<T>(ref T field, T value, [CallerMemberName] string name = null)
        {
            if (Equals(field, value))
            {
                return;
            }
            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        protected void Raise(string name)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public sealed class ServerItem : Observable
    {
        private string _ping = "";
        private bool _isSelected;
        private readonly IList<ProxyLink> _group;

        /// <summary>A single server.</summary>
        public ServerItem(ProxyLink link, Subscription owner)
        {
            Link = link;
            Owner = owner;
        }

        /// <summary>The "auto" entry of a subscription: Xray picks the best of <paramref name="group"/>.</summary>
        public ServerItem(Subscription owner, IList<ProxyLink> group)
        {
            Owner = owner;
            _group = group;
        }

        /// <summary>Null for the "auto" entry.</summary>
        public ProxyLink Link { get; }
        public Subscription Owner { get; }

        public bool IsAuto => _group != null;

        /// <summary>Persisted selection key.</summary>
        public string Key => IsAuto ? "auto:" + Owner.Id : Link.Raw;

        /// <summary>Servers to connect to.</summary>
        public IList<ProxyLink> Links => IsAuto ? _group : new[] { Link };

        public string Name => IsAuto ? "auto — " + Owner.Name : Link.Name;

        public string Detail
        {
            get
            {
                if (IsAuto)
                {
                    var mode = AppSettings.Current.BalancerStrategy == "leastLoad" ? "least load" : "least ping";
                    var count = System.Math.Min(_group.Count, VpnService.MaxBalancedServers);
                    return "best of " + count + " servers · " + mode;
                }
                var transport = Link.Protocol == "hysteria2" ? "quic" : Link.Param("type", "tcp");
                var security = Link.Param("security", Link.Protocol == "trojan" || Link.Protocol == "hysteria2" ? "tls" : "");
                var parts = Link.Protocol.ToUpperInvariant() + " · " + transport + (security != "" && security != "none" ? " · " + security : "");
                return parts + " · " + Owner.Name;
            }
        }

        /// <summary>Segoe MDL2 glyph shown before the name.</summary>
        public string Glyph => IsAuto ? "\uE945" : "";

        public string Ping
        {
            get { return _ping; }
            set { Set(ref _ping, value); }
        }

        public bool IsSelected
        {
            get { return _isSelected; }
            set
            {
                Set(ref _isSelected, value);
                Raise(nameof(MarkerOpacity));
            }
        }

        /// <summary>Opacity of the accent bar shown next to the selected server.</summary>
        public double MarkerOpacity => _isSelected ? 1 : 0;

        public void RefreshDetail()
        {
            Raise(nameof(Detail));
        }
    }

    public sealed class SubscriptionItem : Observable
    {
        public SubscriptionItem(Subscription model)
        {
            Model = model;
        }

        public Subscription Model { get; }

        public string Name => Model.Name;
        public string Summary => Model.Summary;
        public string Url => Model.IsManual ? "" : Model.Url;

        public void Refresh()
        {
            Raise(nameof(Name));
            Raise(nameof(Summary));
        }
    }
}
